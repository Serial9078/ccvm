"""Opt-in integration check for the disposable GitHub Actions PostgreSQL service."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import URL

from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory

BACKEND = Path(__file__).resolve().parents[1]
ARTIFACTS = BACKEND / "integration-artifacts"


def ci_database_url(environ):
    """Never accept DATABASE_URL, DB_* settings, or a caller-supplied database URL."""
    if environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("PostgreSQL integration is restricted to GitHub Actions")
    run_id = environ.get("GITHUB_RUN_ID", "")
    attempt = environ.get("GITHUB_RUN_ATTEMPT", "")
    port = environ.get("CCVM_POSTGRES_TEST_PORT", "")
    if not re.fullmatch(r"[1-9][0-9]{0,19}", run_id):
        raise ValueError("Missing or invalid GitHub run ID")
    if not re.fullmatch(r"[1-9][0-9]{0,9}", attempt):
        raise ValueError("Missing or invalid GitHub run attempt")
    if not re.fullmatch(r"[0-9]{1,5}", port) or not 1024 <= int(port) <= 65535:
        raise ValueError("Missing or invalid mapped PostgreSQL service port")
    return URL.create(
        "postgresql+psycopg2",
        username="ccvm_ci",
        password="ccvm_ci_only",
        host="127.0.0.1",
        port=int(port),
        database=f"ccvm_ci_{run_id}_{attempt}",
        query={
            "connect_timeout": "5",
            "hostaddr": "127.0.0.1",
        },
    )


def alembic_command(url, *args, log_name=None, expect_success=True):
    # Run the real env.py in a fresh process, separate from SQLite unit-test imports.
    environ = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("PG", "DB_")) and key != "DATABASE_URL"
    }
    environ["DATABASE_URL"] = url.render_as_string(hide_password=False)
    environ["PGOPTIONS"] = "-c search_path=public -c statement_timeout=30000 -c lock_timeout=5000"
    log = ARTIFACTS / f"alembic-{log_name or '-'.join(args)}.log"
    try:
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", "alembic.ini", *args],
            cwd=BACKEND,
            env=environ,
            text=True,
            capture_output=True,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        # TimeoutExpired may carry bytes even when text=True.
        output = b"\n".join(
            part.encode() if isinstance(part, str) else part
            for part in (error.stdout, error.stderr)
            if part
        ).decode(errors="replace")
        log.write_text(output + "\nAlembic exceeded the 120-second timeout.\n")
        print(output, flush=True)
        raise AssertionError(f"alembic {' '.join(args)} exceeded 120 seconds") from error
    output = result.stdout + result.stderr
    print(f"alembic {' '.join(args)} (exit {result.returncode})\n{output}", flush=True)
    log.write_text(output)
    if expect_success:
        assert result.returncode == 0, f"alembic {' '.join(args)} failed; see captured output"
    else:
        assert result.returncode != 0, f"alembic {' '.join(args)} unexpectedly succeeded"
    return output


def schema_snapshot(connection):
    inspector = sa.inspect(connection)
    return {
        table: {
            "columns": [
                {
                    "name": column["name"],
                    "type": str(column["type"]),
                    "nullable": column["nullable"],
                    "default": column["default"],
                }
                for column in inspector.get_columns(table)
            ],
            "primary_key": inspector.get_pk_constraint(table),
            "foreign_keys": inspector.get_foreign_keys(table),
            "unique_constraints": inspector.get_unique_constraints(table),
            "indexes": inspector.get_indexes(table),
        }
        for table in inspector.get_table_names(schema="public")
    }


def compare_defaults(context, inspected, metadata, inspected_default, metadata_default, rendered):
    # Existing asset migration deliberately keeps these two backfill defaults.
    # Accept only their exact PostgreSQL values, not arbitrary default drift.
    asset_defaults = {
        "environment": "'production'::character varying",
        "criticality": "'medium'::character varying",
    }
    if metadata.table.name == "assets" and metadata.name in asset_defaults:
        if metadata_default is None and inspected_default == asset_defaults[metadata.name]:
            return False
    return None


def assert_schema_matches_models(connection):
    from app import models  # noqa: F401  # Register all expected tables only after URL isolation.
    from app.database.session import Base

    context = MigrationContext.configure(
        connection,
        opts={"compare_type": True, "compare_server_default": compare_defaults},
    )
    differences = compare_metadata(context, Base.metadata)
    if differences:
        for index in Base.metadata.tables["urls"].indexes:
            if index.unique:
                print(f"Expected URL index: {context.impl._compile_element(index.expressions[1])}")
        print(f"Observed URL indexes: {sa.inspect(connection).get_indexes('urls')}")
    assert not differences, f"Migrated schema differs from ORM metadata: {differences!r}"
    inspector = sa.inspect(connection)
    assert set(inspector.get_table_names()) == set(Base.metadata.tables) | {"alembic_version"}
    for table in Base.metadata.sorted_tables:
        actual = inspector.get_pk_constraint(table.name)["constrained_columns"]
        assert actual == [column.name for column in table.primary_key], table.name


def assert_postgresql_behavior(connection):
    """Exercise native types and constraints that SQLite cannot prove."""
    with connection.begin_nested():
        customer_id = connection.scalar(
            sa.text("INSERT INTO customers (name) VALUES ('CI Customer') RETURNING id")
        )
        domain_id = connection.scalar(
            sa.text(
                "INSERT INTO domains (customer_id, name) VALUES (:customer, 'example.test') "
                "RETURNING id"
            ),
            {"customer": customer_id},
        )
        host_id = connection.scalar(
            sa.text(
                "INSERT INTO hosts (customer_id, domain_id, hostname, alive) "
                "VALUES (:customer, :domain, 'www.example.test', true) RETURNING id"
            ),
            {"customer": customer_id, "domain": domain_id},
        )
        assert connection.scalar(sa.text("SELECT alive FROM hosts WHERE id=:id"), {"id": host_id})
        assert connection.scalar(sa.text("SELECT pg_typeof(alive)::text FROM hosts LIMIT 1")) == (
            "boolean"
        )
        assert connection.scalar(sa.text("SELECT created_at FROM customers LIMIT 1")).tzinfo
        url_id = connection.scalar(
            sa.text(
                "INSERT INTO urls (customer_id, domain_id, host_id, url, method, source) "
                "VALUES (:customer, :domain, :host, 'https://example.test/', 'GET', 'ci') "
                "RETURNING id"
            ),
            {"customer": customer_id, "domain": domain_id, "host": host_id},
        )
        assert_neptun_persistence(connection, url_id, domain_id)
        invalid_statements = [
            # PostgreSQL enforces VARCHAR length; SQLite's VARCHAR(255) does not.
            (
                "22001",
                "INSERT INTO domains (customer_id, name) VALUES (:customer, repeat('x', 256))",
            ),
            ("23505", "INSERT INTO domains (customer_id, name) VALUES (:customer, 'example.test')"),
            ("23503", "INSERT INTO domains (customer_id, name) VALUES (-1, 'invalid.test')"),
            (
                "42804",
                "INSERT INTO hosts (customer_id, hostname, alive) VALUES (:customer, 'x', 1)",
            ),
        ]
        for sqlstate, statement in invalid_statements:
            with pytest.raises(sa.exc.DBAPIError) as error, connection.begin_nested():
                connection.execute(sa.text(statement), {"customer": customer_id})
            assert error.value.orig.pgcode == sqlstate, str(error.value)


def assert_neptun_persistence(connection, url_id, domain_id):
    from sqlalchemy.orm import Session

    from app.models.job import Job
    from app.models.url_detail import UrlDetail
    from app.models.url_screenshot import UrlScreenshot
    from app.models.url_security import UrlSecurity
    from app.plugins.headerprobe import build_result, bulk_upsert_security
    from app.plugins.screenshot import upsert_screenshot
    from app.worker.main import claim_next_job

    # Plugin commit() calls release only their savepoints; the test's outer
    # transaction owns these records and is rolled back on connection close.
    with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
        parent = Job(domain_id=domain_id, pipeline_id="ci-pipeline", plugin="dummy")
        session.add(parent)
        session.flush()
        child = Job(
            domain_id=domain_id,
            parent_job_id=parent.id,
            pipeline_id="ci-pipeline",
            plugin="dummy",
        )
        session.add(child)
        session.add(UrlDetail(url_id=url_id, title="PostgreSQL integration", status_code=200))
        session.commit()
        assert claim_next_job(session).id == parent.id
        assert claim_next_job(session) is None
        parent.status = "finished"
        session.commit()
        assert claim_next_job(session).id == child.id

        failed_probe = build_result(url_id, "https://example.test", None, {}, "timeout")
        bulk_upsert_security(session, [failed_probe])
        assert (
            session.scalar(
                sa.select(UrlSecurity.security_score).where(UrlSecurity.url_id == url_id)
            )
            is None
        )
        successful_probe = build_result(url_id, "https://example.test", 200, {}, None)
        bulk_upsert_security(session, [successful_probe])
        assert (
            session.scalar(
                sa.select(sa.func.count())
                .select_from(UrlSecurity)
                .where(UrlSecurity.url_id == url_id)
            )
            == 1
        )
        assert (
            session.scalar(
                sa.select(UrlSecurity.security_score).where(UrlSecurity.url_id == url_id)
            )
            == 5
        )

        upsert_screenshot(session, {"url_id": url_id, "filename": "first.png"})
        upsert_screenshot(session, {"url_id": url_id, "filename": "updated.png"})
        assert (
            session.scalar(
                sa.select(sa.func.count())
                .select_from(UrlScreenshot)
                .where(UrlScreenshot.url_id == url_id)
            )
            == 1
        )
        assert (
            session.scalar(sa.select(UrlScreenshot.filename).where(UrlScreenshot.url_id == url_id))
            == "updated.png"
        )
        assert (
            session.scalar(sa.select(UrlDetail.title).where(UrlDetail.url_id == url_id))
            == "PostgreSQL integration"
        )
        assert_operator_recovery(connection, session, parent, child)
        assert_scan_persistence(session, url_id, domain_id)


def assert_scan_persistence(session, url_id, domain_id):
    """Exercise URLProbe upserts and Nuclei imports with native PostgreSQL types."""
    from app.models.asset import Asset
    from app.models.domain import Domain
    from app.models.finding import Finding
    from app.models.job import Job
    from app.models.url import Url
    from app.models.url_detail import UrlDetail
    from app.plugins import nucleiurl, urlprobe
    from app.schemas.finding import FindingOut

    session.autoflush = False
    domain = session.get(Domain, domain_id)
    original = session.get(Url, url_id)
    stale = Url(
        customer_id=domain.customer_id,
        domain_id=domain_id,
        url="https://example.test/stale",
        status_code=200,
    )
    asset = Asset(customer_id=domain.customer_id, target=original.url)
    job = Job(domain_id=domain_id, plugin="urlprobe", status="running")
    session.add_all([stale, asset, job])
    session.flush()
    session.add(UrlDetail(url_id=stale.id, status_code=200))
    session.commit()
    output = json.dumps(
        {
            "input": original.url,
            "url": original.url,
            "location": "/unvisited",
            "status_code": 204,
            "content-length": 0,
            "time": "120ms",
        }
    )
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            urlprobe.subprocess,
            "run",
            lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, output, ""),
        )
        urlprobe.run_urlprobe(session, job)
    session.expire_all()
    assert job.status == "finished", job.message
    detail = session.scalar(sa.select(UrlDetail).where(UrlDetail.url_id == original.id))
    assert detail.final_url == original.url and detail.content_length == 0
    assert detail.response_time_seconds == pytest.approx(0.12)
    assert (
        session.scalar(sa.select(UrlDetail.status_code).where(UrlDetail.url_id == stale.id)) is None
    )
    assert stale.status_code is None
    assert nucleiurl.select_scan_urls(session, domain) == [original.url]
    result = {
        "template-id": "postgres-ci-template",
        "matched-at": original.url,
        "info": {
            "name": "PostgreSQL synthetic finding",
            "severity": "low",
            "classification": {"cvss-score": 7.5},
        },
    }
    assert nucleiurl.import_nuclei_result(session, job, asset, result) == (True, False)
    assert nucleiurl.import_nuclei_result(session, job, asset, result) == (False, False)
    session.commit()
    finding = session.scalar(sa.select(Finding).where(Finding.asset_id == asset.id))
    assert FindingOut.model_validate(finding).cvss_score == "7.5"
    assert (
        session.scalar(
            sa.select(sa.func.count()).select_from(Finding).where(Finding.asset_id == asset.id)
        )
        == 1
    )
    finding.status = "fixed"
    session.commit()
    assert nucleiurl.import_nuclei_result(session, job, asset, result) == (False, True)
    session.commit()
    assert finding.status == "open"
    print(
        "PostgreSQL scans: URLProbe fresh/stale upserts and idempotent Nuclei imports passed",
        flush=True,
    )


def assert_operator_recovery(connection, session, parent, child):
    """The exact maintenance payload runs only on the disposable CI database."""
    from sqlalchemy.orm import sessionmaker

    from app.models.job import Job

    spec = importlib.util.spec_from_file_location(
        "worker_recovery", BACKEND.parent / "scripts/recover-worker.py"
    )
    recovery = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recovery)
    snapshots = [
        {column.name: getattr(job, column.name) for column in Job.__table__.columns}
        for job in (parent, child)
    ]
    session.commit()
    factory = sessionmaker(bind=connection, join_transaction_mode="create_savepoint")
    code = compile(recovery.RECOVER_IN_BACKEND, "<reviewed-worker-recovery>", "exec")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("app.database.session.SessionLocal", factory)
        changed = json.loads(json.dumps(snapshots))
        changed[1]["progress"] += 1
        patch.setattr(
            sys, "stdin", io.StringIO(json.dumps({"worker_stopped": True, "jobs": changed}))
        )
        with pytest.raises(RuntimeError, match="Job changed since backup"):
            exec(code, {})
        assert connection.scalar(sa.select(Job.status).where(Job.id == child.id)) == "running"

        patch.setattr(
            sys, "stdin", io.StringIO(json.dumps({"worker_stopped": True, "jobs": snapshots}))
        )
        exec(code, {})
    session.expire_all()
    assert parent.status == "finished"
    assert child.status == "failed" and child.progress == 100
    assert child.pipeline_id == "ci-pipeline" and child.parent_job_id == parent.id
    print(
        "PostgreSQL worker recovery: changed-snapshot rollback and selected-job update passed",
        flush=True,
    )


def url_regression_value(chunks=70):
    # Deterministic high-entropy text; repeated characters would compress and
    # could accidentally pass through the old B-tree index.
    return "https://example.test/search?q=" + "".join(
        hashlib.sha256(str(index).encode()).hexdigest() for index in range(chunks)
    )


def all_data_rows(connection):
    snapshot = {}
    for name in sa.inspect(connection).get_table_names():
        if name == "alembic_version":
            continue
        table = sa.Table(name, sa.MetaData(), autoload_with=connection)
        snapshot[name] = [
            dict(row._mapping)
            for row in connection.execute(sa.select(table).order_by(*table.primary_key.columns))
        ]
    return snapshot


def seed_url_upgrade_regression(engine):
    """Keep an existing URL graph committed across the real schema upgrade."""
    from sqlalchemy.orm import Session

    from app.models.customer import Customer
    from app.models.domain import Domain
    from app.models.host import Host
    from app.models.job import Job
    from app.models.url import Url
    from app.models.url_detail import UrlDetail
    from app.models.url_screenshot import UrlScreenshot
    from app.models.url_security import UrlSecurity

    with Session(engine) as session:
        customer = Customer(name="Existing URL Customer")
        session.add(customer)
        session.flush()
        domain = Domain(customer_id=customer.id, name="existing.test")
        session.add(domain)
        session.flush()
        host = Host(
            customer_id=customer.id, domain_id=domain.id, hostname="existing.test", alive=True
        )
        session.add(host)
        session.flush()
        url = Url(
            customer_id=customer.id,
            domain_id=domain.id,
            host_id=host.id,
            url="https://existing.test/preserved",
            method="GET",
            source="katana",
        )
        session.add(url)
        session.flush()
        session.add_all(
            [
                UrlDetail(url_id=url.id, title="Preserved intelligence", status_code=200),
                UrlSecurity(url_id=url.id, security_score=50),
                UrlScreenshot(url_id=url.id, filename="existing.png"),
                Job(
                    domain_id=domain.id,
                    plugin="katana",
                    status="failed",
                    progress=100,
                    message="Existing failed scan retained",
                ),
            ]
        )
        session.commit()
        row = {
            "customer_id": customer.id,
            "domain_id": domain.id,
            "host_id": host.id,
            "url": url_regression_value(),
            "method": "GET",
            "source": "katana",
        }
        # Reproduce the exact pre-fix PostgreSQL error and prove the entire
        # attempted bulk insert rolls back rather than leaving a partial import.
        before = session.scalar(sa.select(sa.func.count()).select_from(Url))
        with pytest.raises(sa.exc.DBAPIError) as error, session.begin_nested():
            session.execute(
                sa.text(
                    "INSERT INTO urls (customer_id, domain_id, host_id, url, method, source) "
                    "VALUES (:customer_id, :domain_id, :host_id, :url, :method, :source) "
                    "ON CONFLICT (domain_id, url) DO NOTHING"
                ),
                row,
            )
        assert error.value.orig.pgcode == "54000", error.value
        assert "uq_urls_domain_url" in str(error.value.orig)
        assert session.scalar(sa.select(sa.func.count()).select_from(Url)) == before
    with engine.connect() as connection:
        return all_data_rows(connection)


def assert_long_url_persistence(connection):
    from sqlalchemy.orm import Session

    from app.database.url_identity import url_digest
    from app.models.domain import Domain
    from app.models.host import Host
    from app.models.job import Job
    from app.models.url import Url
    from app.plugins import katana

    with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
        domain = session.scalar(sa.select(Domain).where(Domain.name == "existing.test"))
        host = session.scalar(sa.select(Host).where(Host.domain_id == domain.id))
        original = url_regression_value()
        changed = original + "&tail=distinct"
        base = {
            "customer_id": domain.customer_id,
            "domain_id": domain.id,
            "host_id": host.id,
            "method": "GET",
            "source": "katana",
        }
        assert (
            katana.bulk_insert_urls(
                session, [{**base, "url": value} for value in (original, original, changed)]
            )
            == 2
        )
        assert katana.bulk_insert_urls(session, [{**base, "url": original}]) == 0
        assert set(session.scalars(sa.select(Url.url))) >= {original, changed}
        # Expression indexing must handle literal backslashes and UTF-8, rather
        # than interpreting bytea escape sequences or requiring pgcrypto.
        for suffix in (
            "",
            r"&q=\xAB\123\\",
            "&q=Grüße/東京",
            "&q=a%2Fb",
            url_regression_value(160),
        ):
            value = original + suffix
            actual = session.scalar(sa.select(url_digest(sa.literal(value))))
            assert bytes(actual) == hashlib.sha256(value.encode()).digest()
            katana.bulk_insert_urls(session, [{**base, "url": value}])
        other = Domain(customer_id=domain.customer_id, name="other-existing.test")
        session.add(other)
        session.flush()
        assert (
            katana.bulk_insert_urls(session, [{**base, "domain_id": other.id, "url": original}])
            == 1
        )
        # Raw SQL and ordinary ORM updates must enforce the same identity.
        record = session.scalar(
            sa.select(Url).where(Url.domain_id == domain.id, Url.url == changed)
        )
        record.url = original + "&updated=1"
        session.commit()
        assert katana.bulk_insert_urls(session, [{**base, "url": record.url}]) == 0
        with pytest.raises(sa.exc.IntegrityError), session.begin_nested():
            session.execute(
                sa.text(
                    "INSERT INTO urls (customer_id, domain_id, url, method, source) "
                    "VALUES (:customer_id, :domain_id, :url, 'GET', 'raw')"
                ),
                {**base, "url": original},
            )
        job = Job(domain_id=domain.id, plugin="katana", status="running")
        session.add(job)
        session.commit()
        discovered = {
            "hostname": host.hostname,
            "url": original + "&pipeline=1",
            "method": "GET",
            "status_code": 200,
            "content_type": "text/html",
        }
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(katana, "collect_host_urls", lambda *args: ([discovered], 0, 0))
            katana.run_katana(session, job)
        assert job.status == "finished" and job.progress == 100, job.message
        print(
            "PostgreSQL Katana: long URLs, literal text, domain identity and job completion passed",
            flush=True,
        )


def assert_operator_readonly_snapshot(connection):
    spec = importlib.util.spec_from_file_location(
        "update_url_index", BACKEND.parent / "scripts/update-url-index.py"
    )
    operator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(operator)
    before = all_data_rows(connection)
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        exec(compile(operator.STATE_CODE, "<operator-read-only-snapshot>", "exec"), {})
    snapshot = json.loads(output.getvalue())
    operator.validate_state(snapshot, expected=operator.REVISION)
    assert snapshot["tables"]["urls"]["count"] == len(before["urls"])
    assert all_data_rows(connection) == before
    print("Operator read-only row fingerprints and URL index verification passed", flush=True)


def finding_operator():
    spec = importlib.util.spec_from_file_location(
        "finding_url_operator", BACKEND.parent / "scripts/update-header-findings.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def seed_finding_url_regression(engine):
    """Reproduce the production VARCHAR error before widening the column."""
    from sqlalchemy.orm import Session

    from app.models.asset import Asset
    from app.models.domain import Domain
    from app.models.finding import Finding
    from app.models.job import Job
    from app.models.url import Url
    from app.models.url_detail import UrlDetail
    from app.models.url_security import UrlSecurity
    from app.worker.main import process_job

    with Session(engine, autoflush=False) as session:
        domain = session.scalar(sa.select(Domain).where(Domain.name == "existing.test"))
        asset = Asset(customer_id=domain.customer_id, target="https://existing.test/")
        target = url_regression_value(125).replace("example.test", "existing.test")
        url = Url(customer_id=domain.customer_id, domain_id=domain.id, url=target)
        job = Job(domain_id=domain.id, plugin="headerfindings", status="running")
        session.add_all([asset, url, job])
        session.flush()
        existing = Finding(
            asset_id=asset.id,
            scanner="headerprobe",
            template_id="ccvm-missing-csp",
            name="Existing header finding",
            host="https://existing.test",
            matched_at="https://existing.test/preserved",
            status="fixed",
        )
        session.add_all(
            [
                existing,
                UrlDetail(url_id=url.id, content_type="text/html", final_url=target),
                UrlSecurity(url_id=url.id, checked_url=target, security_score=5),
            ]
        )
        session.commit()
        job_id = job.id
        process_job(session, job)
        assert session.get(Job, job_id).status == "failed", job.message
        assert job.progress == 100 and "DataError" in job.message
        assert "character varying(1024)" in job.message
        assert existing.status == "fixed" and existing.matched_at.endswith("/preserved")
        assert session.scalar(sa.select(sa.func.count()).select_from(Finding)) == 1
        print(
            "Reproduced PostgreSQL 22001 for finding URL; worker persisted failed status",
            flush=True,
        )


def assert_finding_url_persistence(connection):
    from sqlalchemy.orm import Session

    from app.models.asset import Asset
    from app.models.domain import Domain
    from app.models.finding import Finding
    from app.models.job import Job
    from app.plugins import nucleiurl
    from app.worker.main import process_job

    with Session(
        bind=connection, autoflush=False, join_transaction_mode="create_savepoint"
    ) as session:
        domain = session.scalar(sa.select(Domain).where(Domain.name == "existing.test"))
        asset = session.scalar(sa.select(Asset).where(Asset.customer_id == domain.customer_id))
        existing = session.scalar(sa.select(Finding).where(Finding.asset_id == asset.id))
        existing_id = existing.id
        job = Job(domain_id=domain.id, plugin="headerfindings", status="running")
        session.add(job)
        session.commit()
        process_job(session, job)
        assert job.status == "finished" and job.progress == 100, job.message
        target = url_regression_value(125).replace("example.test", "existing.test")
        assert session.get(Finding, existing_id).status == "open"
        assert session.get(Finding, existing_id).matched_at == target
        findings = session.scalars(sa.select(Finding).where(Finding.asset_id == asset.id)).all()
        assert len(findings) == 6 and all(row.matched_at == target for row in findings)
        result = {
            "template-id": "ci-long-url",
            "matched-at": target,
            "info": {"name": "Long finding URL", "severity": "low"},
        }
        assert nucleiurl.import_nuclei_result(session, job, asset, result) == (True, False)
        assert nucleiurl.import_nuclei_result(session, job, asset, result) == (False, False)
        session.commit()
        assert (
            session.scalar(
                sa.select(Finding.matched_at).where(
                    Finding.scanner == "nuclei-url", Finding.asset_id == asset.id
                )
            )
            == target
        )
        assert (
            session.scalar(
                sa.select(Finding.host).where(
                    Finding.scanner == "nuclei-url", Finding.asset_id == asset.id
                )
            )
            == "https://existing.test"
        )
        print("PostgreSQL HeaderFindings and Nuclei retained full >8KB finding URLs", flush=True)


def assert_header_resume_transaction(connection, mode="header"):
    """Run the operator's exact recovery transaction, including changed-row refusal."""
    from sqlalchemy.orm import Session

    from app.models.domain import Domain
    from app.models.job import Job
    from app.worker.main import claim_next_job

    operator = finding_operator()
    position, old_status, old_progress = 7, "running", 10
    if mode == "nuclei":
        spec = importlib.util.spec_from_file_location(
            "nuclei_template_operator", BACKEND.parent / "scripts/update-nuclei-templates.py"
        )
        operator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(operator)
        position, old_status, old_progress = 9, "failed", 100
    with connection.begin_nested() as fixture_transaction:
        with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
            domain = session.scalar(sa.select(Domain).where(Domain.name == "existing.test"))
            jobs = []
            for index, plugin in enumerate(operator.STAGES):
                job = Job(
                    domain_id=domain.id,
                    pipeline_id=f"ci-{mode}-resume",
                    plugin=plugin,
                    parent_job_id=jobs[-1].id if jobs else None,
                    status=(
                        "finished"
                        if index < position
                        else old_status if index == position else "queued"
                    ),
                    progress=100 if index < position else old_progress if index == position else 0,
                    message=(
                        (
                            "Correlating security headers for 119 HTML URLs"
                            if mode == "header"
                            else "Nuclei URL scan incomplete: hard timeout after 1200s. "
                            "[ERR] Could not read nuclei-ignore file: no such file"
                        )
                        if index == position
                        else ""
                    ),
                    worker="ccvm-worker-01" if index <= position else None,
                )
                session.add(job)
                session.flush()
                jobs.append(job)
            session.commit()
            rows = [
                {column.name: getattr(job, column.name) for column in Job.__table__.columns}
                for job in jobs
            ]
            selection = (jobs[position].id, jobs[position].uuid)
            state = {"jobs": rows, "active": rows[7:] if mode == "header" else []}
            assert operator.selected_pipeline(state, selection) == rows

            class ExistingTransactionEngine:
                @contextlib.contextmanager
                def begin(self):
                    with connection.begin_nested():
                        yield connection

            with pytest.MonkeyPatch.context() as patch:
                patch.setattr("app.database.session.engine", ExistingTransactionEngine())
                changed = json.loads(json.dumps(rows))
                changed[-1]["progress"] = 1
                with pytest.raises(RuntimeError, match="Pipeline changed since backup"):
                    exec(
                        compile(
                            operator.requeue_source(changed, selection),
                            "<header-resume-reject-changed-snapshot>",
                            "exec",
                        ),
                        {},
                    )
                session.expire_all()
                assert (
                    jobs[position].status == old_status and jobs[position].progress == old_progress
                )
                exec(
                    compile(
                        operator.requeue_source(rows, selection),
                        "<header-resume-transaction>",
                        "exec",
                    ),
                    {},
                )
            session.expire_all()
            assert jobs[position].status == "queued" and jobs[position].progress == 0
            assert jobs[position].worker is None and jobs[position].uuid == selection[1]
            for before, job in zip(rows, jobs, strict=True):
                for field in set(before) - (
                    {"status", "progress", "message", "worker"} if job.id == selection[0] else set()
                ):
                    assert getattr(job, field) == before[field]
            assert claim_next_job(session).id == selection[0]
        fixture_transaction.rollback()
    print(
        f"PostgreSQL selected {mode} retry preserved UUID, dependencies and other jobs",
        flush=True,
    )
    if mode == "header":
        assert_header_resume_transaction(connection, mode="nuclei")


def assert_finding_downgrade_refuses_truncation(engine, url):
    with engine.begin() as connection:
        existing = connection.execute(
            sa.text(
                "SELECT id, matched_at FROM findings WHERE scanner='headerprobe' "
                "ORDER BY id LIMIT 1"
            )
        ).one()
        connection.execute(
            sa.text("UPDATE findings SET matched_at=:value WHERE id=:id"),
            {"value": url_regression_value(125), "id": existing.id},
        )
        before = all_data_rows(connection)
    output = alembic_command(
        url,
        "downgrade",
        "bc64c6f0e217",
        log_name="downgrade-refuses-long-finding-url",
        expect_success=False,
    )
    assert "finding URLs exceed 1024 characters" in output
    with engine.begin() as connection:
        assert all_data_rows(connection) == before
        assert_schema_matches_models(connection)
        assert MigrationContext.configure(connection).get_current_heads() == (
            finding_operator().REVISION,
        )
        # Restore only this disposable test value so the older URL-index
        # downgrade refusal can be exercised independently in the same CI DB.
        connection.execute(
            sa.text("UPDATE findings SET matched_at=:value WHERE id=:id"),
            {"value": existing.matched_at, "id": existing.id},
        )
    print("PostgreSQL downgrade refused URL truncation and preserved all rows", flush=True)


def assert_downgrade_preserves_long_urls(engine, url):
    with engine.begin() as connection:
        domain = connection.execute(
            sa.text("SELECT id, customer_id FROM domains WHERE name='existing.test'")
        ).one()
        connection.execute(
            sa.text(
                "INSERT INTO urls (customer_id, domain_id, url, method, source) "
                "VALUES (:customer, :domain, :url, 'GET', 'downgrade-regression')"
            ),
            {"customer": domain.customer_id, "domain": domain.id, "url": url_regression_value()},
        )
        before = all_data_rows(connection)
    output = alembic_command(
        url,
        "downgrade",
        "7f91c32a60d1",
        log_name="downgrade-refuses-long-url",
        expect_success=False,
    )
    assert "ProgramLimitExceeded" in output
    with engine.connect() as connection:
        assert MigrationContext.configure(connection).get_current_heads() == (
            finding_operator().REVISION,
        )
        assert all_data_rows(connection) == before
        assert_schema_matches_models(connection)
    print("PostgreSQL downgrade refusal preserved schema, long URLs and dependent rows", flush=True)


def test_empty_postgresql_database_migrates_to_head():
    url = ci_database_url(os.environ)  # Guard runs before any connection or application import.
    for key in tuple(os.environ):
        if key.startswith(("PG", "DB_")):
            del os.environ[key]
    os.environ["DATABASE_URL"] = url.render_as_string(hide_password=False)
    ARTIFACTS.mkdir(exist_ok=True)
    engine = sa.create_engine(
        url,
        poolclass=sa.pool.NullPool,
        connect_args={
            "options": "-c search_path=public -c statement_timeout=30000 -c lock_timeout=5000"
        },
    )
    try:
        with engine.connect() as connection:
            identity = connection.execute(
                sa.text(
                    "SELECT current_database(), current_user, current_setting('server_version')"
                )
            ).one()
            print(f"Isolated PostgreSQL identity: {identity!r}", flush=True)
            assert identity[0] == url.database and identity[1] == url.username
            assert identity[2].split(".")[0] == "16", identity[2]
            relations = connection.execute(
                sa.text(
                    "SELECT n.nspname, c.relname FROM pg_class c "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' "
                    "AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')"
                )
            ).all()
            assert not relations, f"Refusing to migrate a nonempty test database: {relations!r}"

        script = ScriptDirectory.from_config(Config(str(BACKEND / "alembic.ini")))
        expected_heads = set(script.get_heads())
        assert len(expected_heads) == 1, f"Expected one revision head: {expected_heads!r}"
        alembic_command(url, "upgrade", "7f91c32a60d1", log_name="upgrade-from-empty")
        existing_rows = seed_url_upgrade_regression(engine)
        alembic_command(url, "upgrade", "bc64c6f0e217", log_name="upgrade-url-index")
        with engine.connect() as connection:
            assert all_data_rows(connection) == existing_rows
            assert_operator_readonly_snapshot(connection)
        seed_finding_url_regression(engine)
        with engine.connect() as connection:
            existing_rows = all_data_rows(connection)
        alembic_command(url, "upgrade", "head", log_name="upgrade-existing-urls")
        alembic_command(url, "current", "--verbose")
        alembic_command(url, "heads", "--verbose")
        with engine.connect() as connection:
            actual_heads = set(MigrationContext.configure(connection).get_current_heads())
            assert actual_heads == expected_heads, (actual_heads, expected_heads)
            assert_schema_matches_models(connection)
            assert all_data_rows(connection) == existing_rows
            assert_finding_url_persistence(connection)
            assert_header_resume_transaction(connection)
            assert_long_url_persistence(connection)
            assert_postgresql_behavior(connection)
            # The outer transaction rolls back all smoke-test data on connection close.
        from integration.operator_docker import assert_paused_worker_maintenance

        assert_paused_worker_maintenance(url)
        alembic_command(url, "upgrade", "head", log_name="upgrade-at-head")
        with engine.connect() as connection:
            assert set(MigrationContext.configure(connection).get_current_heads()) == expected_heads
            assert_schema_matches_models(connection)
        assert_finding_downgrade_refuses_truncation(engine, url)
        assert_downgrade_preserves_long_urls(engine, url)
    finally:
        try:
            with engine.connect() as connection:
                snapshot = schema_snapshot(connection)
                (ARTIFACTS / "schema.json").write_text(json.dumps(snapshot, indent=2, default=str))
                print(f"Observed tables: {sorted(snapshot)!r}", flush=True)
        except Exception as error:
            print(f"Schema diagnostics unavailable: {error!r}", flush=True)
        engine.dispose()
