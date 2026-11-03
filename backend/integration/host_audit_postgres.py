"""Native bytea/JSON and non-destructive downgrade checks; synthetic accounts only."""

import base64

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from app.api.v1.host_audits import create_credential, start_audit
from app.models.customer import Customer
from app.models.host_audit import AuditCredential
from app.plugins.hostinventory import run_hostinventory
from app.schemas.host_audit import CredentialCreate, HostAuditCreate
from app.services import audit_vault, host_inventory

SECRET = "synthetic-pg-inventory-fixture"


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
    print(
        "Seeded existing completed network jobs and service evidence before inventory migration",
        flush=True,
    )


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
    print(
        "PostgreSQL authenticated inventory: bytea encryption, JSON evidence, revocation retention",
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
