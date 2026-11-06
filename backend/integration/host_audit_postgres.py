"""Native bytea/JSON and non-destructive downgrade checks; synthetic accounts only."""

import base64
import hashlib
import json
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from app.api.v1.host_audits import create_credential, start_audit
from app.models.customer import Customer
from app.models.host_audit import AuditCredential, HostAudit
from app.plugins.hostinventory import run_hostinventory
from app.schemas.host_audit import CredentialCreate, HostAuditCreate
from app.services import audit_vault, host_inventory

SECRET = "synthetic-pg-inventory-fixture"


def seed_legacy_inventory_history(engine):
    """Write old-layout SSH/HTTPS runs before the new transport column exists."""
    from app.models.asset import Asset
    from app.models.job import Job

    fixtures = {"audits": [], "jobs": [], "assets": [], "credentials": []}
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"i" * 32).decode())
        patch.setenv("CCVM_NETWORK_ALLOWED_CIDRS", "192.0.2.0/24")
        with Session(engine) as db:
            customer = Customer(name="Retained before WinRM transport migration")
            db.add(customer)
            db.flush()
            fixtures["customer"] = customer.id
            old_table = sa.Table("host_audits", sa.MetaData(), autoload_with=db.connection())
            assert "winrm_transport" not in old_table.c
            for index, (kind, status) in enumerate(
                [("ssh_password", "queued"), ("winrm", "queued"), ("winrm", "finished")],
                start=21,
            ):
                credential = create_credential(
                    CredentialCreate(
                        customer_id=customer.id,
                        name=f"Retained {kind} {index}",
                        kind=kind,
                        username="inventory",
                        allowed_cidrs=["192.0.2.0/24"],
                        password=SECRET,
                    ),
                    db,
                )
                target = f"192.0.2.{index}"
                asset = Asset(customer_id=customer.id, type="ip", target=target, ip_address=target)
                db.add(asset)
                db.flush()
                job = Job(
                    asset_id=asset.id,
                    plugin="hostinventory",
                    status=status,
                    progress=100 if status == "finished" else 0,
                    message="Retained inventory fixture",
                )
                db.add(job)
                db.flush()
                audit = SimpleNamespace(
                    customer_id=customer.id,
                    asset_id=asset.id,
                    credential_id=credential.id,
                    job_id=job.id,
                    target=target,
                    port=5986 if kind == "winrm" else 22,
                    ssh_fingerprint=None if kind == "winrm" else "SHA256:" + "A" * 43,
                    mode="inventory",
                )
                # Exact original deployed serialization; no transport attribute.
                old_hash = hashlib.sha256(
                    json.dumps(
                        [
                            "ccvm-host-inventory-v1",
                            audit.customer_id,
                            audit.asset_id,
                            audit.job_id,
                            credential.uuid,
                            hashlib.sha256(audit_vault.identity(credential)).hexdigest(),
                            hashlib.sha256(credential.ciphertext).hexdigest(),
                            audit.target,
                            audit.port,
                            audit.ssh_fingerprint,
                            audit.mode,
                        ],
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest()
                stored = windows_evidence() if status == "finished" else None
                audit_id = db.scalar(
                    old_table.insert()
                    .values(
                        **vars(audit),
                        scope_sha256=old_hash,
                        cancel_requested=False,
                        inventory=stored,
                    )
                    .returning(old_table.c.id)
                )
                fixtures["audits"].append(audit_id)
                fixtures["jobs"].append(job.id)
                fixtures["assets"].append(asset.id)
                fixtures["credentials"].append(credential.id)
                db.commit()
    return fixtures


def assert_legacy_inventory_history(engine, fixtures):
    """Prove old frozen hashes and history survive without widening a connection."""
    from app.models.asset import Asset
    from app.models.job import Job

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"i" * 32).decode())
        patch.setenv("CCVM_NETWORK_ALLOWED_CIDRS", "192.0.2.0/24")

        def collect(payload, cancelled):
            assert payload["winrm_transport"] == "https"
            assert not cancelled()
            return windows_evidence() if payload["kind"] == "winrm" else evidence()

        patch.setattr(host_inventory, "collect", collect)
        with Session(engine) as db:
            for audit_id in fixtures["audits"]:
                audit = db.get(HostAudit, audit_id)
                assert audit.winrm_transport == "https"
                assert audit.scope_sha256 == audit_vault.audit_hash(audit, audit.credential)
                assert audit_vault.decrypt(audit.credential) == {"password": SECRET}
                if audit.job.status == "queued":
                    run_hostinventory(db, audit.job)
                    db.refresh(audit)
                assert audit.job.status == "finished"
                assert audit.inventory["os"]["name"] == "Synthetic Linux"
            # Remove only this disposable fixture once preservation is proved.
            for model, key in (
                (HostAudit, "audits"),
                (Job, "jobs"),
                (Asset, "assets"),
                (AuditCredential, "credentials"),
            ):
                db.execute(sa.delete(model).where(model.id.in_(fixtures[key])))
            db.execute(sa.delete(Customer).where(Customer.id == fixtures["customer"]))
            db.commit()
    print(
        "PostgreSQL transport migration preserved old queued SSH/HTTPS hashes, "
        "encrypted credentials and completed Windows evidence",
        flush=True,
    )


def seed_network_history(engine):
    from app.api.v1.network_scans import start_scan
    from app.models.asset import Asset
    from app.models.host import Host
    from app.models.network_scan import NetworkObservation, NetworkScan
    from app.schemas.network_scan import NetworkScanCreate

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("CCVM_NETWORK_ALLOWED_CIDRS", "192.0.2.0/24")
        with Session(engine) as db:
            customer = Customer(name="Retained pre-inventory network history")
            db.add(customer)
            db.commit()
            result = start_scan(
                NetworkScanCreate(
                    customer_id=customer.id, target="192.0.2.11", profile="custom", ports="22"
                ),
                db,
            )
            scan = db.get(NetworkScan, result["id"])
            for job in (scan.discovery_job, scan.audit_job):
                job.status, job.progress, job.message = "finished", 100, "Retained network fixture"
            host = Host(
                customer_id=customer.id,
                hostname="retained-host",
                ip_address="192.0.2.11",
                source="nmap-network",
                alive=True,
            )
            asset = Asset(
                customer_id=customer.id, type="ip", target="192.0.2.11", ip_address="192.0.2.11"
            )
            db.add_all([host, asset])
            db.flush()
            db.add(
                NetworkObservation(
                    scan_id=scan.id,
                    host_id=host.id,
                    asset_id=asset.id,
                    ip_address="192.0.2.11",
                    services=[
                        {
                            "port": 22,
                            "state": "open",
                            "service": "ssh",
                            "method": "probed",
                            "checks": [
                                {
                                    "check": "ssh2-enum-algos",
                                    "status": "completed",
                                    "output": "retained fixture evidence",
                                }
                            ],
                        }
                    ],
                )
            )
            db.commit()
            identities = {
                "scan": scan.id,
                "customer": customer.id,
                "host": host.id,
                "ip_asset": asset.id,
                "network_asset": scan.asset_id,
                "discovery": scan.discovery_job_id,
                "audit": scan.audit_job_id,
            }
    print(
        "Seeded existing completed network jobs and service evidence before inventory migration",
        flush=True,
    )
    return identities


def remove_network_fixture(engine, identities):
    """Remove only this disposable fixture after its migration preservation proof.

    The subsequent historical operator test intentionally downgrades an empty
    network schema. Real retained history must (and does) block that downgrade.
    """
    from app.models.asset import Asset
    from app.models.host import Host
    from app.models.job import Job
    from app.models.network_scan import NetworkObservation, NetworkScan

    with Session(engine) as db:
        scan = db.get(NetworkScan, identities["scan"])
        assert scan.customer_id == identities["customer"] and scan.target == "192.0.2.11/32"
        assert scan.discovery_job.status == scan.audit_job.status == "finished"
        for model, column, values in (
            (NetworkObservation, NetworkObservation.scan_id, [identities["scan"]]),
            (NetworkScan, NetworkScan.id, [identities["scan"]]),
            (Job, Job.id, [identities["audit"]]),
            (Job, Job.id, [identities["discovery"]]),
            (Host, Host.id, [identities["host"]]),
            (Asset, Asset.id, [identities["ip_asset"], identities["network_asset"]]),
            (Customer, Customer.id, [identities["customer"]]),
        ):
            db.execute(sa.delete(model).where(column.in_(values)))
        db.commit()


def seed(db):
    customer = Customer(name="Synthetic authenticated inventory")
    db.add(customer)
    db.commit()
    credential = create_credential(
        CredentialCreate(
            customer_id=customer.id,
            name="CI credential",
            kind="ssh_password",
            username="inventory",
            allowed_cidrs=["192.0.2.0/24"],
            password=SECRET,
        ),
        db,
    )
    audit = start_audit(
        HostAuditCreate(
            customer_id=customer.id,
            credential_id=credential.id,
            target="192.0.2.1",
            ssh_fingerprint="SHA256:" + "A" * 43,
        ),
        db,
    )
    return credential, audit


def evidence(*args, **kwargs):
    return {
        "schema_version": 1,
        "os": {
            "family": "Linux",
            "name": "Synthetic Linux",
            "version": "1",
            "kernel": "1.0",
            "architecture": "x86_64",
            "hostname": "fixture",
        },
        "packages": {
            "status": "complete",
            "source": "dpkg",
            "items": [
                {
                    "name": "synthetic-package",
                    "version": "1:2.3-4",
                    "architecture": "amd64",
                }
            ],
        },
        "hotfixes": {"status": "not_applicable", "source": "none", "items": []},
    }


def windows_evidence():
    result = evidence()
    result["os"]["family"] = "Windows"
    result["packages"]["source"] = "registry-uninstall"
    result["hotfixes"] = {"status": "complete", "source": "Get-HotFix", "items": []}
    return result


def assert_native_inventory(connection):
    with connection.begin_nested():
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"i" * 32).decode())
            patch.setenv("CCVM_NETWORK_ALLOWED_CIDRS", "192.0.2.0/24")
            patch.setattr(host_inventory, "collect", evidence)
            with Session(bind=connection, join_transaction_mode="create_savepoint") as db:
                credential, audit = seed(db)
                assert SECRET.encode() not in credential.ciphertext
                assert audit_vault.decrypt(credential) == {"password": SECRET}
                assert (
                    connection.scalar(
                        sa.text(
                            "SELECT pg_typeof(ciphertext)::text FROM audit_credentials WHERE id=:id"
                        ),
                        {"id": credential.id},
                    )
                    == "bytea"
                )
                run_hostinventory(db, audit.job)
                db.refresh(audit)
                assert audit.job.status == "finished"
                assert audit.inventory["packages"]["items"][0]["version"] == "1:2.3-4"
                assert (
                    connection.scalar(
                        sa.text("SELECT pg_typeof(inventory)::text FROM host_audits WHERE id=:id"),
                        {"id": audit.id},
                    )
                    == "json"
                )
                assert audit.completed_at is not None
                # A revoked account loses its ciphertext while historical
                # evidence and the immutable credential reference remain.
                credential.enabled = False
                credential.ciphertext = None
                db.commit()
                db.expire_all()
                assert db.get(AuditCredential, credential.id).ciphertext is None
                assert audit.inventory["os"]["name"] == "Synthetic Linux"
                windows_credential = create_credential(
                    CredentialCreate(
                        customer_id=audit.customer_id,
                        name="Synthetic Windows HTTP credential",
                        kind="winrm",
                        username="LAB\\inventory",
                        allowed_cidrs=["192.0.2.0/24"],
                        password=SECRET,
                    ),
                    db,
                )
                http_audit = start_audit(
                    HostAuditCreate(
                        customer_id=audit.customer_id,
                        credential_id=windows_credential.id,
                        target="192.0.2.2",
                        winrm_transport="http_ntlm",
                    ),
                    db,
                )
                assert http_audit.port == 5985
                patch.setattr(host_inventory, "collect", lambda *a, **kw: windows_evidence())
                run_hostinventory(db, http_audit.job)
                db.refresh(http_audit)
                assert http_audit.job.status == "finished"
                assert http_audit.inventory["os"]["family"] == "Windows"
                assert http_audit.winrm_transport == "http_ntlm"
                assert http_audit.scope_sha256 == audit_vault.audit_hash(
                    http_audit, windows_credential
                )
    print(
        "PostgreSQL authenticated inventory: bytea encryption, JSON evidence, "
        "revocation retention, explicit HTTP WinRM history",
        flush=True,
    )


def assert_downgrade_retains_inventory(engine, url, command, rows, schema):
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"i" * 32).decode())
        patch.setenv("CCVM_NETWORK_ALLOWED_CIDRS", "192.0.2.0/24")
        with Session(engine) as db:
            seed(db)
    with engine.connect() as connection:
        before = rows(connection)
    output = command(
        url,
        "downgrade",
        "f93b70a4e628",
        log_name="host-inventory-retains-evidence",
        expect_success=False,
    )
    assert "Credential/inventory history exists" in output
    with engine.connect() as connection:
        assert rows(connection) == before
        schema(connection)
    print(
        "PostgreSQL downgrade refused to discard encrypted credentials and inventory history",
        flush=True,
    )


def assert_downgrade_retains_http_transport(engine, url, command, rows, schema):
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"i" * 32).decode())
        patch.setenv("CCVM_NETWORK_ALLOWED_CIDRS", "192.0.2.0/24")
        with Session(engine) as db:
            customer = Customer(name="Retained HTTP transport downgrade fixture")
            db.add(customer)
            db.commit()
            credential = create_credential(
                CredentialCreate(
                    customer_id=customer.id,
                    name="Retained HTTP Windows credential",
                    kind="winrm",
                    username="LAB\\inventory",
                    allowed_cidrs=["192.0.2.0/24"],
                    password=SECRET,
                ),
                db,
            )
            start_audit(
                HostAuditCreate(
                    customer_id=customer.id,
                    credential_id=credential.id,
                    target="192.0.2.3",
                    winrm_transport="http_ntlm",
                ),
                db,
            )
    with engine.connect() as connection:
        before = rows(connection)
    output = command(
        url,
        "downgrade",
        "a4c1d8e7f209",
        log_name="host-inventory-retains-http-transport",
        expect_success=False,
    )
    assert "HTTP WinRM history exists" in output
    with engine.connect() as connection:
        assert rows(connection) == before
        schema(connection)
    print("PostgreSQL downgrade refused to discard HTTP WinRM transport history", flush=True)
