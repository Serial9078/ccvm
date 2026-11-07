"""Native catalog/assessment storage and retention; synthetic public fixtures only."""

import base64
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from app.api.v1.host_audits import create_credential, start_audit
from app.models.customer import Customer
from app.models.finding import Finding
from app.models.host_assessment import HostAssessment, WindowsPatchCatalog
from app.models.job import Job
from app.schemas.host_audit import CredentialCreate, HostAuditCreate
from app.services import audit_vault, host_inventory


def catalog_fixture(now=None):
    """A deliberately synthetic normalized MSRC document, never fetched from a host."""
    now = now or datetime.now(UTC)
    month = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    document = f"{now.year}-{month[now.month - 1]}"
    source = f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{document}"
    released = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    return {
        "schema_version": 1,
        "source": "msrc-cvrf",
        "retrieved_at": now.isoformat(),
        "coverage_start": now.replace(day=1).date().isoformat(),
        "coverage_end": now.date().isoformat(),
        "documents": [
            {
                "id": document,
                "url": source,
                "sha256": "a" * 64,
                "current_release_date": released,
                "initial_release_date": released,
            }
        ],
        "entries": [
            {
                "product_id": "11923",
                "product_name": "Windows Server 2022",
                "cve": "CVE-2026-00001",
                "title": "Synthetic published Windows update advisory",
                "severity": "high",
                "cvss_score": "7.5",
                "kb": "KB5010000",
                "fixed_build": "10.0.20348.2000",
                "document_id": document,
                "source_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-00001",
                "subtype": "Security Update",
            }
        ],
    }


def seed_saved_windows_inventory(db):
    """Seed already-collected evidence; do not open a remote connection."""
    customer = Customer(name="Synthetic Windows patch assessment customer")
    db.add(customer)
    db.commit()
    credential = create_credential(
        CredentialCreate(
            customer_id=customer.id,
            name="Synthetic retained Windows account",
            kind="winrm",
            username="EXAMPLE\\inventory",
            allowed_cidrs=["192.0.2.0/24"],
            password="synthetic-patch-assessment-password",
        ),
        db,
    )
    audit = start_audit(
        HostAuditCreate(
            customer_id=customer.id,
            credential_id=credential.id,
            target="192.0.2.31",
            winrm_transport="http_ntlm",
        ),
        db,
    )
    audit.inventory = {
        "schema_version": 1,
        "os": {
            "family": "Windows",
            "name": "Microsoft Windows Server 2022 Standard",
            "version": "10.0.20348",
            "kernel": "20348.1000",
            "architecture": "64-bit",
            "hostname": "SYNTHETIC-WINDOWS",
            "product_type": "3",
            "installation_type": "Server",
            "edition_id": "ServerStandard",
            "native_architecture": "AMD64",
            "sku": "7",
            "display_version": "21H2",
        },
        "packages": {"status": "complete", "source": "registry-uninstall", "items": []},
        "hotfixes": {"status": "complete", "source": "Get-HotFix", "items": []},
    }
    audit.completed_at = datetime.now(UTC)
    audit.job.status, audit.job.progress = "finished", 100
    audit.job.message = "Previously collected synthetic Windows inventory"
    db.commit()
    return audit, credential


def assert_assessment_storage(db):
    from app.api.v1.host_assessments import create_assessment, list_assessments
    from app.services.windows_patch_sync import canonical_bytes, store_catalog

    catalog = store_catalog(db, catalog_fixture())
    same = store_catalog(db, catalog.payload)
    assert same.id == catalog.id
    audit, credential = seed_saved_windows_inventory(db)
    before = canonical_bytes(audit.inventory)
    source = canonical_bytes(catalog.payload)
    ciphertext, scope = credential.ciphertext, audit.scope_sha256
    jobs = db.scalar(sa.select(sa.func.count()).select_from(Job))
    findings = db.scalar(sa.select(sa.func.count()).select_from(Finding))

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Assessment must not use target credentials or recollect inventory")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(audit_vault, "decrypt", forbidden)
        patch.setattr(host_inventory, "collect", forbidden)
        first = create_assessment(audit.id, None, db)
        again = create_assessment(audit.id, None, db)
    assert first["id"] == again["id"]
    assert first["catalog_id"] == catalog.id
    assert first["status"] == "build_gap"
    assert first["evidence_sha256"] == hashlib.sha256(before).hexdigest()
    assert list_assessments(audit.id, db)[0]["id"] == first["id"]
    db.expire_all()
    assert canonical_bytes(audit.inventory) == before
    assert canonical_bytes(catalog.payload) == source
    assert credential.ciphertext == ciphertext and audit.scope_sha256 == scope
    assert db.scalar(sa.select(sa.func.count()).select_from(Job)) == jobs
    assert db.scalar(sa.select(sa.func.count()).select_from(Finding)) == findings
    assert audit.job.status == "finished" and audit.job.progress == 100
    assert db.get(HostAssessment, first["id"]).result == first["result"]
    if db.get_bind().dialect.name == "postgresql":
        for table, column, identity in (
            ("windows_patch_catalogs", "payload", catalog.id),
            ("host_assessments", "result", first["id"]),
        ):
            actual = db.scalar(
                sa.text(f"SELECT pg_typeof({column})::text FROM {table} WHERE id=:id"),
                {"id": identity},
            )
            assert actual == "json"
    return first


def assert_native_patch_assessment(connection):
    with connection.begin_nested(), pytest.MonkeyPatch.context() as patch:
        patch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"i" * 32).decode())
        patch.setenv("CCVM_NETWORK_ALLOWED_CIDRS", "192.0.2.0/24")
        with Session(bind=connection, join_transaction_mode="create_savepoint") as db:
            assert_assessment_storage(db)
    print(
        "PostgreSQL patch assessment: native JSON, catalog/run idempotence, "
        "immutable evidence/credentials and no new scan jobs/findings",
        flush=True,
    )


def assert_downgrade_retains_patch_history(engine, url, command, rows, schema):
    from app.services.windows_patch_sync import store_catalog

    with Session(engine) as db:
        store_catalog(db, catalog_fixture(datetime.now(UTC) - timedelta(minutes=1)))
    for stage in ("catalog", "assessment"):
        if stage == "assessment":
            with pytest.MonkeyPatch.context() as patch:
                patch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"i" * 32).decode())
                patch.setenv("CCVM_NETWORK_ALLOWED_CIDRS", "192.0.2.0/24")
                with Session(engine) as db:
                    assert_assessment_storage(db)
        with engine.connect() as connection:
            before = rows(connection)
        output = command(
            url,
            "downgrade",
            "b7e2c9d1a630",
            log_name=f"host-patch-retains-{stage}-history",
            expect_success=False,
        )
        assert "Patch catalog/assessment history exists" in output
        with engine.connect() as connection:
            assert rows(connection) == before
            schema(connection)
            assert connection.scalar(sa.select(sa.func.count()).select_from(WindowsPatchCatalog))
    print("PostgreSQL downgrade refused to discard catalog and assessment history", flush=True)
