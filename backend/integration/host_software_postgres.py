"""Native retention and software assessment checks using synthetic evidence only."""

import base64
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session


def catalog_fixture(now=None):
    """A synthetic normalized source snapshot; no external request is made."""
    now = now or datetime.now(UTC)
    month_names = (
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
    )
    month = f"{now.year}-{month_names[now.month - 1]}"
    cve = "CVE-2026-0001"
    cve_source = (
        "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/0xxx/" f"{cve}.json"
    )
    document_id = f"msrc:{month}"
    return {
        "schema_version": 1,
        "source": "vendor-software-ranges",
        "rules_version": "windows-registry-v1",
        "retrieved_at": now.isoformat(),
        "coverage_start": now.replace(day=1).date().isoformat(),
        "coverage_end": now.date().isoformat(),
        "documents": [
            {
                "id": document_id,
                "url": f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{month}",
                "sha256": "a" * 64,
            },
            {"id": f"cve:{cve}", "url": cve_source, "sha256": "b" * 64},
            {
                "id": "source:7zip-history",
                "url": "https://www.7-zip.org/history.txt",
                "sha256": "c" * 64,
            },
        ],
        "entries": [
            {
                "cve": cve,
                "product_key": "edge-windows",
                "source_product": "Microsoft Edge for Windows",
                "title": "Synthetic software version range advisory",
                "severity": "high",
                "affected_ranges": [{"introduced": "1.0.0.0", "fixed": "152.0.4191.52"}],
                "source_urls": [
                    cve_source,
                    f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}",
                ],
                "document_ids": [f"cve:{cve}", document_id],
            }
        ],
        "coverage": [
            {
                "product_key": "edge-windows",
                "discovered": 1,
                "parsed": 1,
                "unavailable_cves": [],
                "scope": "Synthetic monthly Edge version range coverage",
            },
            {
                "product_key": "7zip-windows",
                "discovered": 1,
                "parsed": 0,
                "unavailable_cves": ["CVE-2025-55188"],
                "scope": "Curated single advisory: CVE-2025-55188",
            },
        ],
    }


def seed_saved_software_inventory(db):
    from integration.host_patch_postgres import seed_saved_windows_inventory

    audit, credential = seed_saved_windows_inventory(db)
    inventory = dict(audit.inventory)
    inventory["packages"] = {
        "status": "complete",
        "source": "registry-uninstall",
        "items": [
            {
                "name": "Microsoft Edge",
                "version": "150.0.1.2",
                "architecture": "unknown",
                "publisher": "Microsoft Corporation",
                "registry_key": "Microsoft Edge",
                "registry_view": "wow6432",
                "install_scope": "machine",
            },
            {
                "name": "Synthetic unsupported application",
                "version": "1.2.3",
                "architecture": "unknown",
                "publisher": "Synthetic publisher",
                "registry_key": "SyntheticApp",
                "registry_view": "native",
                "install_scope": "machine",
            },
        ],
    }
    audit.inventory = inventory
    db.commit()
    return audit, credential


def seed_retained_patch_history(engine):
    """Commit populated c8 history before the additive software schema exists."""
    from app.api.v1.host_assessments import create_assessment
    from app.services.windows_patch_sync import store_catalog
    from integration.host_patch_postgres import catalog_fixture, seed_saved_windows_inventory

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"i" * 32).decode())
        patch.setenv("CCVM_NETWORK_ALLOWED_CIDRS", "192.0.2.0/24")
        with Session(engine) as db:
            catalog = store_catalog(db, catalog_fixture())
            audit, credential = seed_saved_windows_inventory(db)
            assessment = create_assessment(audit.id, None, db)
            assert assessment["status"] == "build_gap"
            return {
                "customer": audit.customer_id,
                "asset": audit.asset_id,
                "job": audit.job_id,
                "audit": audit.id,
                "credential": credential.id,
                "catalog": catalog.id,
                "assessment": assessment["id"],
            }


def remove_retained_patch_fixture(engine, fixture):
    """Remove only the dedicated disposable fixture after preservation is proved."""
    from app.models.asset import Asset
    from app.models.customer import Customer
    from app.models.host_assessment import HostAssessment, WindowsPatchCatalog
    from app.models.host_audit import AuditCredential, HostAudit
    from app.models.job import Job

    with Session(engine) as db:
        for model, key in (
            (HostAssessment, "assessment"),
            (WindowsPatchCatalog, "catalog"),
            (HostAudit, "audit"),
            (Job, "job"),
            (Asset, "asset"),
            (AuditCredential, "credential"),
            (Customer, "customer"),
        ):
            db.execute(sa.delete(model).where(model.id == fixture[key]))
        db.commit()


def assert_assessment_storage(db):
    from app.api.v1.host_assessments import create_assessment as assess_os
    from app.api.v1.software_assessments import create_assessment, list_assessments
    from app.models.finding import Finding
    from app.models.host_assessment import HostAssessment
    from app.models.job import Job
    from app.models.software_assessment import SoftwareAssessment
    from app.services import audit_vault, host_inventory
    from app.services.software_catalog_sync import canonical_bytes, store_catalog
    from app.services.windows_patch_sync import store_catalog as store_os_catalog
    from integration.host_patch_postgres import catalog_fixture as os_catalog_fixture

    store_os_catalog(db, os_catalog_fixture())
    catalog = store_catalog(db, catalog_fixture())
    assert store_catalog(db, catalog.payload).id == catalog.id
    audit, credential = seed_saved_software_inventory(db)
    os_assessment = assess_os(audit.id, None, db)
    before = canonical_bytes(audit.inventory)
    source = canonical_bytes(catalog.payload)
    os_history = canonical_bytes(db.get(HostAssessment, os_assessment["id"]).result)
    ciphertext, scope = credential.ciphertext, audit.scope_sha256
    jobs = db.scalar(sa.select(sa.func.count()).select_from(Job))
    findings = db.scalar(sa.select(sa.func.count()).select_from(Finding))

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Software assessment must not log in or recollect host evidence")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(audit_vault, "decrypt", forbidden)
        patch.setattr(host_inventory, "collect", forbidden)
        first = create_assessment(audit.id, None, db)
        again = create_assessment(audit.id, None, db)
    assert first["id"] == again["id"]
    assert first["catalog_id"] == catalog.id
    assert first["status"] == "version_matches_found"
    assert first["evidence_sha256"] == hashlib.sha256(before).hexdigest()
    assert first["result"]["summary"]["cve_matches"] == 1
    assert first["result"]["summary"]["unassessed_entries"] == 1
    assert first["result"]["products"][0]["matches"][0]["cve"] == "CVE-2026-0001"
    assert list_assessments(audit.id, db)[0]["id"] == first["id"]
    db.expire_all()
    assert canonical_bytes(audit.inventory) == before
    assert canonical_bytes(catalog.payload) == source
    assert canonical_bytes(db.get(HostAssessment, os_assessment["id"]).result) == os_history
    assert credential.ciphertext == ciphertext and audit.scope_sha256 == scope
    assert db.scalar(sa.select(sa.func.count()).select_from(Job)) == jobs
    assert db.scalar(sa.select(sa.func.count()).select_from(Finding)) == findings
    assert audit.job.status == "finished" and audit.job.progress == 100
    assert db.get(SoftwareAssessment, first["id"]).result == first["result"]
    if db.get_bind().dialect.name == "postgresql":
        for table, column, identity in (
            ("software_advisory_catalogs", "payload", catalog.id),
            ("software_assessments", "result", first["id"]),
        ):
            actual = db.scalar(
                sa.text(f"SELECT pg_typeof({column})::text FROM {table} WHERE id=:id"),
                {"id": identity},
            )
            assert actual == "json"
    return first


def assert_native_software_assessment(connection):
    with connection.begin_nested(), pytest.MonkeyPatch.context() as patch:
        patch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"i" * 32).decode())
        patch.setenv("CCVM_NETWORK_ALLOWED_CIDRS", "192.0.2.0/24")
        with Session(bind=connection, join_transaction_mode="create_savepoint") as db:
            assert_assessment_storage(db)
    print(
        "PostgreSQL software assessment: native JSON, catalog/run idempotence, "
        "retained OS history, immutable evidence/credentials and no new jobs/findings",
        flush=True,
    )


def assert_downgrade_retains_software_history(engine, url, command, rows, schema):
    from app.api.v1.software_assessments import create_assessment
    from app.models.software_assessment import SoftwareAdvisoryCatalog, SoftwareAssessment
    from app.services.software_catalog_sync import store_catalog

    for stage in ("catalog", "assessment"):
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"i" * 32).decode())
            patch.setenv("CCVM_NETWORK_ALLOWED_CIDRS", "192.0.2.0/24")
            with Session(engine) as db:
                if stage == "catalog":
                    store_catalog(db, catalog_fixture(datetime.now(UTC) - timedelta(minutes=1)))
                    assert db.query(SoftwareAssessment).count() == 0
                else:
                    # Prove the assessment-only branch with a NULL catalog FK,
                    # independently of the preceding catalog-preservation guard.
                    db.execute(sa.delete(SoftwareAdvisoryCatalog))
                    db.commit()
                    audit, _credential = seed_saved_software_inventory(db)
                    saved = create_assessment(audit.id, None, db)
                    assert saved["catalog_id"] is None
                    assert db.query(SoftwareAdvisoryCatalog).count() == 0
        with engine.connect() as connection:
            before = rows(connection)
        output = command(
            url,
            "downgrade",
            "c8f3a0e2b741",
            log_name=f"software-retains-{stage}-history",
            expect_success=False,
        )
        assert "Software catalog/assessment history exists" in output
        with engine.connect() as connection:
            assert rows(connection) == before
            schema(connection)
    print(
        "PostgreSQL downgrade refused to discard software catalogs and assessment history",
        flush=True,
    )
