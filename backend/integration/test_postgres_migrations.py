"""Opt-in integration check for the disposable GitHub Actions PostgreSQL service."""

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


def alembic_command(url, *args, log_name=None):
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
    assert result.returncode == 0, f"alembic {' '.join(args)} failed; see captured output"


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
        assert session.scalar(sa.select(UrlSecurity.security_score)) is None
        successful_probe = build_result(url_id, "https://example.test", 200, {}, None)
        bulk_upsert_security(session, [successful_probe])
        assert session.scalar(sa.select(sa.func.count()).select_from(UrlSecurity)) == 1
        assert session.scalar(sa.select(UrlSecurity.security_score)) == 5

        upsert_screenshot(session, {"url_id": url_id, "filename": "first.png"})
        upsert_screenshot(session, {"url_id": url_id, "filename": "updated.png"})
        assert session.scalar(sa.select(sa.func.count()).select_from(UrlScreenshot)) == 1
        assert session.scalar(sa.select(UrlScreenshot.filename)) == "updated.png"
        assert session.scalar(sa.select(UrlDetail.title)) == "PostgreSQL integration"
        assert_operator_recovery(connection, session, parent, child)


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
        alembic_command(url, "upgrade", "head", log_name="upgrade-from-empty")
        alembic_command(url, "current", "--verbose")
        alembic_command(url, "heads", "--verbose")
        with engine.connect() as connection:
            actual_heads = set(MigrationContext.configure(connection).get_current_heads())
            assert actual_heads == expected_heads, (actual_heads, expected_heads)
            assert_schema_matches_models(connection)
            assert_postgresql_behavior(connection)
            # The outer transaction rolls back all smoke-test data on connection close.
        alembic_command(url, "upgrade", "head", log_name="upgrade-at-head")
        with engine.connect() as connection:
            assert set(MigrationContext.configure(connection).get_current_heads()) == expected_heads
            assert_schema_matches_models(connection)
    finally:
        try:
            with engine.connect() as connection:
                snapshot = schema_snapshot(connection)
                (ARTIFACTS / "schema.json").write_text(json.dumps(snapshot, indent=2, default=str))
                print(f"Observed tables: {sorted(snapshot)!r}", flush=True)
        except Exception as error:
            print(f"Schema diagnostics unavailable: {error!r}", flush=True)
        engine.dispose()
