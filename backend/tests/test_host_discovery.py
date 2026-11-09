"""Private implementation coverage and evidence-bound discovery without probing."""

import base64
import copy
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import event

from app.database.deps import get_db
from app.main import app
from app.models.asset import Asset
from app.models.customer import Customer
from app.models.finding import Finding
from app.models.host import Host
from app.models.host_audit import AuditCredential, HostAudit
from app.models.job import Job
from app.models.network_scan import NetworkObservation, NetworkScan
from app.services import audit_vault, host_inventory, scanner_capabilities
from app.services.windows_patch_sync import canonical_bytes

TOKEN = "synthetic-discovery-token-private-only"


@pytest.fixture
def secured(client, monkeypatch):
    monkeypatch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"p" * 32).decode())
    monkeypatch.setenv("CCVM_AUDIT_OPERATOR_TOKEN", TOKEN)
    monkeypatch.setenv("CCVM_NETWORK_ALLOWED_CIDRS", "192.0.2.0/24,2001:db8::/120")
    client.base_url = httpx.URL("https://testserver")
    client.headers["Authorization"] = f"Bearer {TOKEN}"
    return client


@pytest.fixture
def db(client):
    return next(app.dependency_overrides[get_db]())


def scan(secured, customer, db, target="192.0.2.0/24", created=None):
    response = secured.post(
        "/api/v1/network-scans",
        json={"customer_id": customer["id"], "target": target, "profile": "fast"},
    )
    assert response.status_code == 201, response.text
    row = db.get(NetworkScan, response.json()["id"])
    row.created_at = created or datetime.now(UTC) - timedelta(minutes=1)
    row.discovery_job.status = "finished"
    row.audit_job.status = "finished"
    db.commit()
    return row


def service(port=22, **changes):
    return {
        "port": port,
        "protocol": "tcp",
        "state": "open",
        "service": "ssh",
        "method": "probed",
        "product": "Reported product only",
        "version": "1.2.3",
        "checks": [],
        **changes,
    }


def observe(db, row, address="192.0.2.10", services=None, *, existing_asset=None):
    asset = existing_asset or Asset(
        customer_id=row.customer_id, target=address, ip_address=address, type="ip"
    )
    host = Host(
        customer_id=row.customer_id,
        hostname=address,
        ip_address=address,
        source="nmap-network",
        alive=True,
    )
    db.add_all([asset, host])
    db.flush()
    observation = NetworkObservation(
        scan_id=row.id,
        host_id=host.id,
        asset_id=asset.id,
        ip_address=address,
        services=[service()] if services is None else services,
    )
    db.add(observation)
    db.commit()
    return observation


def inventory(db, asset, *, status="finished", evidence=None, mode="inventory", created=None):
    credential = AuditCredential(
        customer_id=asset.customer_id,
        name="Synthetic private credential",
        kind="winrm",
        username="never-include-this-account",
        allowed_cidrs=["192.0.2.0/24"],
        ciphertext=b"never-include-this-ciphertext",
    )
    job = Job(asset_id=asset.id, plugin="hostinventory", status=status, progress=100)
    db.add_all([credential, job])
    db.flush()
    audit = HostAudit(
        customer_id=asset.customer_id,
        asset_id=asset.id,
        credential_id=credential.id,
        job_id=job.id,
        target=asset.target,
        port=5985,
        winrm_transport="http_ntlm",
        mode=mode,
        scope_sha256="a" * 64,
        inventory=evidence,
        created_at=created or datetime.now(UTC),
        completed_at=datetime.now(UTC) if status in {"finished", "failed"} else None,
    )
    db.add(audit)
    db.commit()
    return audit


def evidence(**changes):
    return {
        "os": {"family": "Windows", "hostname": "SYNTHETIC-HOST"},
        "packages": {"status": "complete", "items": []},
        "hotfixes": {"status": "complete", "items": []},
        **changes,
    }


def get(secured, customer_id, **params):
    response = secured.get(
        "/api/v1/host-audits/discovered", params={"customer_id": customer_id, **params}
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    return response.json()


@pytest.mark.parametrize("suffix", ["capabilities", "discovered?customer_id=1"])
def test_routes_require_operator_tls_and_do_not_cache(secured, suffix):
    path = "/api/v1/host-audits/" + suffix
    response = secured.get(path, headers={"Authorization": "Bearer invalid"})
    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"
    secured.base_url = httpx.URL("http://testserver")
    response = secured.get(path, headers={"X-Forwarded-Proto": "https"})
    assert response.status_code == 403
    assert response.headers["cache-control"] == "no-store"


def test_registry_is_explicit_coverage_not_host_verdict(secured):
    response = secured.get("/api/v1/host-audits/capabilities")
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    data = response.json()
    assert data["version"] == "scanner-capabilities-v1"
    rows = {row["id"]: row["stages"] for row in data["platforms"]}
    assert set(rows) == {
        "domains",
        "urls",
        "network",
        "windows_server",
        "windows_client",
        "linux",
        "vmware",
        "other_devices",
    }
    stages = {row["id"] for row in data["stage_labels"]}
    assert stages == {
        "discovery",
        "inventory",
        "configuration",
        "os_baseline",
        "software_checks",
        "offered_updates",
    }
    assert all(set(row) == stages for row in rows.values())
    assert rows["windows_server"]["os_baseline"]["status"] == "limited"
    assert rows["windows_client"]["os_baseline"]["status"] == "unavailable"
    assert rows["windows_client"]["offered_updates"]["provider"] == "windows-update-agent"
    assert rows["windows_server"]["offered_updates"]["provider"] == "windows-update-agent"
    for platform in ("linux", "vmware", "other_devices"):
        assert rows[platform]["os_baseline"]["status"] == "unavailable"
        assert rows[platform]["software_checks"]["status"] == "unavailable"
        assert rows[platform]["offered_updates"]["status"] == "unavailable"
    assert rows["linux"]["inventory"]["status"] == "limited"
    assert rows["vmware"]["inventory"]["status"] == "unavailable"
    assert "UDP" in str(rows["network"]["discovery"]["limitations"])
    original = scanner_capabilities.capabilities()
    changed = scanner_capabilities.capabilities()
    changed["platforms"][0]["stages"]["discovery"]["limitations"].append("changed")
    assert scanner_capabilities.capabilities() == original


def test_cim_discovery_shows_partial_coverage_after_successful_identity_read(secured, customer, db):
    row = scan(secured, customer, db)
    observation = observe(db, row)
    audit = inventory(
        db,
        db.get(Asset, observation.asset_id),
        mode="cim_inventory",
        evidence=evidence(packages={"status": "not_requested", "items": []}),
    )
    device = get(secured, customer["id"])["items"][0]
    assert device["host_audit_id"] == audit.id
    assert device["inventory_status"] == "partial"


def test_only_positive_network_observations_are_devices(secured, customer, db):
    row = scan(secured, customer, db)
    positive = observe(db, row, services=[service(3389, service="ms-wbt-server")])
    observe(db, row, "192.0.2.11", [])
    observe(db, row, "192.0.2.12", [service(state="closed")])
    observe(db, row, "192.0.2.13", [service(state="filtered")])
    observe(db, row, "192.0.2.14", [service(protocol="udp")])
    # Even an existing live asset without network evidence is not a discovery.
    db.add(Asset(customer_id=customer["id"], type="ip", target="192.0.2.15"))
    db.commit()
    data = get(secured, customer["id"])
    assert data["total"] == 1 and len(data["items"]) == 1
    item = data["items"][0]
    assert item["asset_id"] == positive.asset_id
    assert item["ip_address"] == "192.0.2.10" and item["scan_id"] == row.id
    assert item["services"][0]["port"] == 3389
    assert item["inventory_status"] == "not_inventoried"
    assert item["host_audit_id"] is None and item["inventory_collected_at"] is None
    assert "platform" not in item and "hostname" not in item and "os" not in item


def test_latest_positive_observation_not_later_silence_is_selected(secured, customer, db):
    now = datetime.now(UTC)
    first = scan(secured, customer, db, created=now - timedelta(hours=3))
    observe(db, first, services=[service(version="old")])
    second = scan(secured, customer, db, created=now - timedelta(hours=2))
    observe(db, second, services=[service(version="latest-positive")])
    third = scan(secured, customer, db, created=now - timedelta(hours=1))
    observe(db, third, services=[])
    item = get(secured, customer["id"])["items"][0]
    assert item["scan_id"] == second.id
    assert item["services"][0]["version"] == "latest-positive"
    assert item["last_seen"].startswith(second.created_at.strftime("%Y-%m-%dT%H:%M:%S"))


def test_pagination_counts_unique_positive_ips_and_is_customer_bound(secured, customer, db):
    first = scan(secured, customer, db)
    for index in range(1, 6):
        observe(db, first, f"192.0.2.{index}")
    other = Customer(name="Other synthetic customer")
    db.add(other)
    db.commit()
    other_scan = scan(secured, {"id": other.id}, db)
    observe(db, other_scan, "192.0.2.200")
    data = get(secured, customer["id"], limit=2, offset=1)
    assert data["total"] == 5 and data["limit"] == 2 and data["offset"] == 1
    assert data["has_more"] and len(data["items"]) == 2
    assert [item["ip_address"] for item in data["items"]] == ["192.0.2.4", "192.0.2.3"]
    assert get(secured, customer["id"], limit=2, offset=4)["has_more"] is False
    assert get(secured, customer["id"], offset=50)["items"] == []
    assert get(secured, other.id)["total"] == 1
    for query in ("", "?customer_id=0", "?customer_id=1&limit=201", "?customer_id=1&offset=-1"):
        assert secured.get("/api/v1/host-audits/discovered" + query).status_code == 422
    assert secured.get("/api/v1/host-audits/discovered?customer_id=99999").status_code == 404


def test_ipv6_literal_evidence_supported_without_current_scan_permission(
    secured, customer, db, monkeypatch
):
    row = scan(secured, customer, db, target="2001:db8::/126")
    observe(db, row, "2001:db8::1")
    monkeypatch.delenv("CCVM_NETWORK_ALLOWED_CIDRS")
    assert get(secured, customer["id"])["items"][0]["ip_address"] == "2001:db8::1"


@pytest.mark.parametrize(
    "mutation",
    [
        "root_customer",
        "root_target",
        "asset_customer",
        "asset_target",
        "asset_type",
        "host_customer",
        "host_source",
        "host_ip",
        "job_asset",
        "job_plugin",
        "job_pipeline",
        "audit_parent",
        "targets",
        "hash",
        "outside",
    ],
)
def test_inconsistent_discovery_bindings_fail_closed(secured, customer, db, mutation):
    row = scan(secured, customer, db)
    observation = observe(db, row)
    asset, host, root = (
        db.get(Asset, observation.asset_id),
        db.get(Host, observation.host_id),
        db.get(Asset, row.asset_id),
    )
    other = Customer(name="Other synthetic customer")
    db.add(other)
    db.flush()
    if mutation == "root_customer":
        root.customer_id = other.id
    elif mutation == "root_target":
        root.target = "192.0.2.0/25"
    elif mutation == "asset_customer":
        asset.customer_id = other.id
    elif mutation == "asset_target":
        asset.target = "192.0.2.99"
    elif mutation == "asset_type":
        asset.type = "url"
    elif mutation == "host_customer":
        host.customer_id = other.id
    elif mutation == "host_source":
        host.source = "httpx"
    elif mutation == "host_ip":
        host.ip_address = "192.0.2.99"
    elif mutation == "job_asset":
        row.discovery_job.asset_id = asset.id
    elif mutation == "job_plugin":
        row.discovery_job.plugin = "other"
    elif mutation == "job_pipeline":
        row.audit_job.pipeline_id = "changed"
    elif mutation == "audit_parent":
        row.audit_job.parent_job_id = None
    elif mutation == "targets":
        row.targets = ["192.0.2.99"]
    elif mutation == "hash":
        row.scope_sha256 = "0" * 64
    else:
        observation.ip_address = asset.target = asset.ip_address = host.ip_address = "198.51.100.1"
    db.commit()
    response = secured.get("/api/v1/host-audits/discovered", params={"customer_id": customer["id"]})
    assert response.status_code == 409
    assert "Other synthetic customer" not in response.text
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "status,evidence_value,mode,expected",
    [
        ("running", None, "inventory", "pending"),
        ("failed", None, "inventory", "failed"),
        ("finished", evidence(), "inventory", "inventoried"),
        ("finished", evidence(), "windows_updates", "inventoried"),
        ("failed", evidence(packages={"status": "partial"}), "inventory", "partial"),
        ("finished", evidence(packages={"status": "partial"}), "inventory", "partial"),
    ],
)
def test_latest_inventory_state_is_not_security_verdict(
    secured, customer, db, status, evidence_value, mode, expected
):
    row = scan(secured, customer, db)
    observation = observe(db, row)
    asset = db.get(Asset, observation.asset_id)
    # A newer connection test cannot replace an actual inventory state.
    audit = inventory(db, asset, status=status, evidence=evidence_value, mode=mode)
    inventory(db, asset, mode="connection", created=datetime.now(UTC) + timedelta(seconds=1))
    item = get(secured, customer["id"])["items"][0]
    assert item["inventory_status"] == expected and item["host_audit_id"] == audit.id
    assert "patch_status" not in item and "safe" not in item


def test_read_has_no_decryption_network_writes_or_raw_evidence(secured, customer, db, monkeypatch):
    row = scan(secured, customer, db)
    observation = observe(
        db,
        row,
        services=[
            service(
                product="reported\x00\x1b-product",
                checks=[
                    {
                        "status": "completed",
                        "output": "never-include-raw-output",
                        "xml": "never-include-raw-xml",
                    }
                ],
            )
        ],
    )
    asset = db.get(Asset, observation.asset_id)
    audit = inventory(db, asset, evidence=evidence())
    before = canonical_bytes(copy.deepcopy(audit.inventory))
    counts = (db.query(Job).count(), db.query(Finding).count(), db.query(HostAudit).count())

    def forbidden(*_args, **_kwargs):
        pytest.fail("Discovery must not authenticate, decrypt, collect or create jobs/findings")

    monkeypatch.setattr(audit_vault, "decrypt", forbidden)
    monkeypatch.setattr(host_inventory, "collect", forbidden)
    data = get(secured, customer["id"])
    assert counts == (db.query(Job).count(), db.query(Finding).count(), db.query(HostAudit).count())
    assert canonical_bytes(audit.inventory) == before
    content = str(data)
    for secret in ("never-include", "ciphertext", "credential", "packages", "hotfixes"):
        assert secret not in content
    assert data["items"][0]["services"][0]["product"] == "reported-product"
    assert data["items"][0]["services"][0]["audit_coverage"] == "completed"


def test_bounded_service_summary_and_database_query_count(secured, customer, db):
    row = scan(secured, customer, db)
    for index in range(1, 11):
        observe(db, row, f"192.0.2.{index}", [service(port=port) for port in range(1, 81)])
    queries = []

    def executed(_connection, _cursor, statement, _params, _context, _many):
        queries.append(statement)

    event.listen(db.bind, "before_cursor_execute", executed)
    try:
        data = get(secured, customer["id"], limit=10)
    finally:
        event.remove(db.bind, "before_cursor_execute", executed)
    assert data["total"] == 10
    assert all(
        item["services_total"] == 80 and item["services_truncated"] for item in data["items"]
    )
    assert all(len(item["services"]) == 64 for item in data["items"])
    assert len(queries) <= 5, queries
