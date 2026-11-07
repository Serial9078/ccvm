"""Private host overview: exact platform, evidence-bound patch history and no auth."""

import base64
import copy
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import event

from app.api.v1.host_assessments import create_assessment as assess_windows
from app.api.v1.software_assessments import create_assessment as assess_software
from app.database.deps import get_db
from app.main import app
from app.models.asset import Asset
from app.models.customer import Customer
from app.models.finding import Finding
from app.models.host_assessment import HostAssessment
from app.models.host_audit import AuditCredential, HostAudit
from app.models.job import Job
from app.models.software_assessment import SoftwareAssessment
from app.services import audit_vault, host_inventory
from app.services.software_catalog_sync import store_catalog as store_software
from app.services.windows_patch_sync import canonical_bytes
from app.services.windows_patch_sync import store_catalog as store_windows
from integration.host_patch_postgres import catalog_fixture as windows_catalog
from integration.host_software_postgres import catalog_fixture as software_catalog

TOKEN = "synthetic-overview-token-private-only"


@pytest.fixture
def secured(client, monkeypatch):
    monkeypatch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"p" * 32).decode())
    monkeypatch.setenv("CCVM_AUDIT_OPERATOR_TOKEN", TOKEN)
    monkeypatch.setenv("CCVM_NETWORK_ALLOWED_CIDRS", "192.0.2.0/24")
    client.base_url = httpx.URL("https://testserver")
    client.headers["Authorization"] = f"Bearer {TOKEN}"
    return client


@pytest.fixture
def db(client):
    return next(app.dependency_overrides[get_db]())


def inventory(family="Windows", product_type="3"):
    return {
        "schema_version": 1,
        "os": {
            "family": family,
            "name": "Microsoft Windows Server 2022 Standard",
            "hostname": "SYNTHETIC-HOST",
            "version": "10.0.20348",
            "kernel": "20348.1000",
            "architecture": "64-bit",
            "product_type": product_type,
            "installation_type": "Server",
            "edition_id": "ServerStandard",
            "native_architecture": "AMD64",
        },
        "packages": {
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
                }
            ],
        },
        "hotfixes": {"status": "complete", "source": "Get-HotFix", "items": []},
    }


def run(
    db,
    customer_id,
    target="192.0.2.10",
    evidence=None,
    status="finished",
    mode="inventory",
    created=None,
    existing_asset=None,
):
    created = created or datetime.now(UTC) - timedelta(minutes=1)
    asset = existing_asset or Asset(customer_id=customer_id, type="ip", target=target)
    db.add(asset)
    db.flush()
    credential = AuditCredential(
        customer_id=customer_id,
        name="Private fixture",
        kind="winrm",
        username="Never disclose account",
        allowed_cidrs=["192.0.2.0/24"],
        ciphertext=b"private-overview-ciphertext-not-used",
        enabled=True,
    )
    db.add(credential)
    db.flush()
    job = Job(
        asset_id=asset.id,
        plugin="hostinventory",
        status=status,
        progress=100,
        message="Synthetic retained result",
    )
    db.add(job)
    db.flush()
    audit = HostAudit(
        customer_id=customer_id,
        asset_id=asset.id,
        credential_id=credential.id,
        job_id=job.id,
        target=asset.target,
        port=5985,
        winrm_transport="http_ntlm",
        mode=mode,
        scope_sha256="a" * 64,
        inventory=evidence,
        created_at=created,
        completed_at=created if status in {"finished", "failed"} else None,
    )
    db.add(audit)
    db.commit()
    return audit


def snapshots(db):
    now = datetime.now(UTC)
    return store_windows(db, windows_catalog(now)), store_software(db, software_catalog(now))


def get(secured, customer_id, **params):
    response = secured.get(
        "/api/v1/host-audits/overview", params={"customer_id": customer_id, **params}
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def test_overview_static_route_and_empty_result(secured, customer):
    data = get(secured, customer["id"])
    assert data["hosts"] == [] and data["hosts_total"] == 0
    assert data["catalogs"] == {"windows": None, "software": None}
    assert data["issues"] == [] and not data["hosts_truncated"]


def test_overview_requires_tls_operator_and_customer(secured, customer):
    path = f"/api/v1/host-audits/overview?customer_id={customer['id']}"
    response = secured.get(path, headers={"Authorization": "Bearer invalid"})
    assert response.status_code == 401 and response.headers["cache-control"] == "no-store"
    secured.base_url = httpx.URL("http://testserver")
    assert secured.get(path, headers={"X-Forwarded-Proto": "https"}).status_code == 403
    secured.base_url = httpx.URL("https://testserver")
    assert secured.get("/api/v1/host-audits/overview?customer_id=99999").status_code == 404
    for query in ("", "?customer_id=0", "?customer_id=1&limit=501"):
        assert secured.get("/api/v1/host-audits/overview" + query).status_code == 422


@pytest.mark.parametrize(
    "family,product_type,platform",
    [
        ("Windows", "2", "windows_server"),
        ("Windows", "3", "windows_server"),
        ("Windows", "1", "windows_client"),
        ("Windows", "", "unclassified"),
        ("Windows", "9", "unclassified"),
        ("Linux", "3", "linux"),
        ("VMware", "", "vmware"),
        ("ESXi", "", "vmware"),
        ("Other", "3", "unclassified"),
    ],
)
def test_platform_uses_reported_identity_not_caption_or_credential(
    secured, customer, db, family, product_type, platform
):
    run(db, customer["id"], evidence=inventory(family, product_type))
    host = get(secured, customer["id"])["hosts"][0]
    assert host["platform"] == platform
    if platform in {"linux", "vmware"}:
        assert "patch_assessment_unsupported" in host["issues"]
    if platform == "windows_client":
        assert "windows_client_patch_coverage_unavailable" in host["issues"]


def test_failed_empty_inventory_is_unclassified(secured, customer, db):
    audit = run(db, customer["id"], status="failed")
    host = get(secured, customer["id"])["hosts"][0]
    assert host["latest_run"]["id"] == audit.id
    assert host["latest_run"]["port"] == 5985
    assert host["latest_run"]["winrm_transport"] == "http_ntlm"
    assert host["latest_run"]["ssh_fingerprint"] is None
    assert host["platform"] == "unclassified" and host["inventory"] is None
    assert host["windows_assessment"] is None and host["software_assessment"] is None
    assert host["issues"] == ["latest_collection_failed", "inventory_missing"]


def test_current_assessments_are_compact_local_and_immutable(secured, customer, db, monkeypatch):
    windows, software = snapshots(db)
    audit = run(db, customer["id"], evidence=inventory())
    patch, apps = assess_windows(audit.id, None, db), assess_software(audit.id, None, db)
    before = canonical_bytes(audit.inventory)
    jobs, findings = db.query(Job).count(), db.query(Finding).count()
    ciphertext = db.get(AuditCredential, audit.credential_id).ciphertext

    def forbidden(*_args, **_kwargs):
        pytest.fail("Overview must not authenticate, decrypt, collect or create assessments")

    monkeypatch.setattr(audit_vault, "decrypt", forbidden)
    monkeypatch.setattr(host_inventory, "collect", forbidden)
    monkeypatch.setattr(HostAssessment, "__init__", forbidden)
    monkeypatch.setattr(SoftwareAssessment, "__init__", forbidden)
    data = get(secured, customer["id"])
    host = data["hosts"][0]
    assert host["inventory"]["id"] == audit.id
    assert host["windows_assessment"]["id"] == patch["id"]
    assert host["windows_assessment"]["status"] == "build_gap"
    assert host["windows_assessment"]["result"]["baseline_kbs"] == ["KB5010000"]
    assert "cve_references" not in host["windows_assessment"]["result"]
    assert host["software_assessment"]["id"] == apps["id"]
    assert host["software_assessment"]["result"]["summary"]["cve_matches"] == 1
    for assessment in (host["windows_assessment"], host["software_assessment"]):
        assert not assessment["expired"]
        assert assessment["current_catalog"] and assessment["evidence_matches"]
        assert assessment["engine_current"]
    assert data["catalogs"]["windows"]["id"] == windows.id
    assert data["catalogs"]["software"]["id"] == software.id
    assert canonical_bytes(audit.inventory) == before
    assert db.get(AuditCredential, audit.credential_id).ciphertext == ciphertext
    assert db.query(Job).count() == jobs and db.query(Finding).count() == findings
    assert "Never disclose account" not in str(data) and "ciphertext" not in str(data)


def test_failed_new_attempt_retains_known_inventory_with_failure_warning(secured, customer, db):
    snapshots(db)
    first = run(
        db, customer["id"], evidence=inventory(), created=datetime.now(UTC) - timedelta(hours=1)
    )
    assessment = assess_windows(first.id, None, db)
    second = run(db, customer["id"], status="failed", existing_asset=db.get(Asset, first.asset_id))
    host = get(secured, customer["id"])["hosts"][0]
    assert host["latest_run"]["id"] == second.id and host["inventory"]["id"] == first.id
    assert host["platform"] == "windows_server"
    assert host["windows_assessment"]["id"] == assessment["id"]
    assert "latest_collection_failed" in host["issues"]


def test_new_inventory_never_inherits_older_assessment(secured, customer, db):
    snapshots(db)
    first = run(
        db, customer["id"], evidence=inventory(), created=datetime.now(UTC) - timedelta(hours=1)
    )
    assess_windows(first.id, None, db)
    assess_software(first.id, None, db)
    newer = inventory()
    newer["os"]["kernel"] = "20348.2000"
    second = run(db, customer["id"], evidence=newer, existing_asset=db.get(Asset, first.asset_id))
    host = get(secured, customer["id"])["hosts"][0]
    assert host["inventory"]["id"] == second.id
    assert host["windows_assessment"] is None and host["software_assessment"] is None


@pytest.mark.parametrize("mutation", ["evidence", "engine", "expired", "future", "catalog"])
def test_stale_or_changed_basis_cannot_appear_current(secured, customer, db, mutation):
    snapshots(db)
    audit = run(db, customer["id"], evidence=inventory())
    saved = assess_windows(audit.id, None, db)
    row = db.get(HostAssessment, saved["id"])
    if mutation == "evidence":
        data = copy.deepcopy(audit.inventory)
        data["os"]["kernel"] = "20348.9999"
        audit.inventory = data
    elif mutation == "engine":
        row.engine_version = "old-engine"
    elif mutation == "expired":
        row.result = {
            **row.result,
            "valid_until": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
        }
    elif mutation == "future":
        audit.completed_at = datetime.now(UTC) + timedelta(days=1)
    else:
        store_windows(db, windows_catalog(datetime.now(UTC) + timedelta(seconds=1)))
    db.commit()
    result = get(secured, customer["id"])["hosts"][0]["windows_assessment"]
    assert not (
        result["evidence_matches"]
        and result["current_catalog"]
        and result["engine_current"]
        and not result["expired"]
    )


def test_stale_partial_inventory_keeps_coverage_limits(secured, customer, db):
    snapshots(db)
    evidence = inventory()
    evidence["packages"]["status"] = "truncated"
    audit = run(
        db,
        customer["id"],
        evidence=evidence,
        status="failed",
        created=datetime.now(UTC) - timedelta(days=9),
    )
    assess_windows(audit.id, None, db)
    host = get(secured, customer["id"])["hosts"][0]
    assert {"inventory_stale", "inventory_partial", "latest_collection_failed"} <= set(
        host["issues"]
    )
    assert host["windows_assessment"]["expired"]


def test_customer_isolation_and_assessment_identity(secured, customer, db):
    snapshots(db)
    audit = run(db, customer["id"], evidence=inventory())
    saved = assess_windows(audit.id, None, db)
    other = Customer(name="Another private customer")
    db.add(other)
    db.commit()
    other_audit = run(db, other.id, target="192.0.2.99", evidence=inventory())
    row = db.get(HostAssessment, saved["id"])
    row.customer_id = other.id
    row.result = {**row.result, "reason": "CROSS-CUSTOMER-PRIVATE"}
    db.commit()
    data = get(secured, customer["id"])
    assert len(data["hosts"]) == 1 and data["hosts"][0]["target"] == audit.target
    assert data["hosts"][0]["windows_assessment"] is None
    assert other_audit.target not in str(data) and "CROSS-CUSTOMER-PRIVATE" not in str(data)


@pytest.mark.parametrize("mutation", ["asset_customer", "target", "job_asset", "job_plugin"])
def test_invalid_host_binding_is_rejected(secured, customer, db, mutation):
    audit = run(db, customer["id"], evidence=inventory())
    if mutation == "target":
        audit.target = "192.0.2.99"
    elif mutation == "job_plugin":
        audit.job.plugin = "dummy"
    else:
        other = Customer(name="Other customer")
        db.add(other)
        db.flush()
        asset = Asset(customer_id=other.id, type="ip", target="192.0.2.99")
        db.add(asset)
        db.flush()
        if mutation == "asset_customer":
            db.get(Asset, audit.asset_id).customer_id = other.id
        else:
            audit.job.asset_id = asset.id
    db.commit()
    response = secured.get("/api/v1/host-audits/overview", params={"customer_id": customer["id"]})
    assert response.status_code == 409
    assert "192.0.2.99" not in response.text and response.headers["cache-control"] == "no-store"


def test_explicit_limit_and_connection_checks_do_not_replace_inventory(secured, customer, db):
    first = run(
        db, customer["id"], evidence=inventory(), created=datetime.now(UTC) - timedelta(hours=1)
    )
    latest = run(
        db,
        customer["id"],
        mode="connection",
        evidence=inventory(),
        existing_asset=db.get(Asset, first.asset_id),
    )
    run(db, customer["id"], target="192.0.2.11", evidence=inventory())
    data = get(secured, customer["id"], limit=1)
    assert data["limit"] == 1 and data["hosts_total"] == 2 and data["hosts_truncated"]
    host = next(
        row for row in get(secured, customer["id"])["hosts"] if row["asset_id"] == first.asset_id
    )
    assert host["latest_run"]["id"] == latest.id and host["inventory"]["id"] == first.id


def test_catalog_corruption_blocks_current_claims_without_hiding_inventory(secured, customer, db):
    windows, _ = snapshots(db)
    audit = run(db, customer["id"], evidence=inventory())
    assess_windows(audit.id, None, db)
    windows.sha256 = "f" * 64
    db.commit()
    data = get(secured, customer["id"])
    assert data["catalogs"]["windows"] is None and "windows_catalog_invalid" in data["issues"]
    assert not data["hosts"][0]["windows_assessment"]["current_catalog"]
    assert data["hosts"][0]["inventory"]["id"] == audit.id


def test_overview_select_queries_are_constant_per_request(secured, customer, db):
    run(db, customer["id"], evidence=inventory())
    statements = []

    def record(_connection, _cursor, statement, _parameters, _context, _many):
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)

    engine = db.get_bind()
    event.listen(engine, "before_cursor_execute", record)
    try:
        get(secured, customer["id"])
        one = len(statements)
        for number in range(20, 30):
            run(db, customer["id"], target=f"192.0.2.{number}", evidence=inventory())
        statements.clear()
        get(secured, customer["id"])
        assert len(statements) == one
    finally:
        event.remove(engine, "before_cursor_execute", record)


def test_actionable_software_is_prioritized_and_truncation_keeps_complete_counts(
    secured, customer, db
):
    snapshots(db)
    audit = run(db, customer["id"], evidence=inventory())
    saved = assess_software(audit.id, None, db)
    row = db.get(SoftwareAssessment, saved["id"])
    affected = row.result["products"][0]
    unassessed = {**affected, "status": "no_match_in_catalog", "matches_total": 0, "matches": []}
    row.result = {**row.result, "products": [unassessed] * 55 + [affected], "products_total": 56}
    db.commit()
    summary = get(secured, customer["id"])["hosts"][0]["software_assessment"]["result"]
    assert len(summary["products"]) == 50 and summary["products_truncated"]
    assert summary["products"][0]["matches_total"] == 1
    assert summary["products_total"] == 56 and summary["summary"]["cve_matches"] == 1


def test_response_size_limit_remains_explicit(secured, customer, db, monkeypatch):
    from app.api.v1 import host_overview

    for number in range(10, 15):
        run(db, customer["id"], target=f"192.0.2.{number}", evidence=inventory())
    monkeypatch.setattr(host_overview, "MAX_RESPONSE", 16385)
    data = get(secured, customer["id"])
    assert data["hosts_truncated"] and data["hosts_total"] == 5
    assert not data["hosts"] and "overview_size_limit" in data["issues"]


def reference_product(*, version="98.0.0.0", fixes=("99.0.0.0", "150.0.0.0")):
    return {
        "product_key": "edge-windows",
        "version": version,
        "matches_truncated": False,
        "matches_total": len(fixes),
        "matches": [
            {"affected_ranges": [{"introduced": "1.0.0.0", "fixed": fixed}]} for fixed in fixes
        ],
    }


def test_reference_fix_uses_numeric_full_matched_bounds_not_lexical_order():
    from app.api.v1.host_overview import _reference_fix

    assert _reference_fix(reference_product()) == ("150.0.0.0", True)


def test_reference_fix_ignores_disjoint_unmatched_ranges():
    from app.api.v1.host_overview import _reference_fix

    product = reference_product(fixes=("100.0.0.0",))
    product["matches"][0]["affected_ranges"].append(
        {"introduced": "150.0.0.0", "fixed": "160.0.0.0"}
    )
    assert _reference_fix(product) == ("100.0.0.0", True)


@pytest.mark.parametrize(
    "mutation",
    [
        "truncated",
        "missing",
        "invalid_version",
        "invalid_range",
        "wrong_product",
        "unmatched_record",
    ],
)
def test_reference_fix_cannot_claim_an_incomplete_or_invalid_target(mutation):
    from app.api.v1.host_overview import _reference_fix

    product = reference_product()
    if mutation == "truncated":
        product["matches_truncated"] = True
    elif mutation == "missing":
        product["matches_total"] += 1
    elif mutation == "invalid_version":
        product["version"] = "98.0.0.x"
    elif mutation == "invalid_range":
        product["matches"][0]["affected_ranges"][0]["fixed"] = "unavailable"
    elif mutation == "wrong_product":
        product["product_key"] = "unknown"
    elif mutation == "unmatched_record":
        product["matches"][0]["affected_ranges"][0]["introduced"] = "99.0.0.0"
    assert _reference_fix(product) == (None, False)


def test_reference_fix_is_based_on_full_retained_matches_before_overview_cap():
    from app.api.v1.host_overview import _software_result

    product = reference_product(
        version="150.0.0.0", fixes=tuple(f"{number}.0.0.0" for number in range(151, 176))
    )
    source = {
        "reason": "Synthetic reference",
        "products": [product],
        "products_total": 1,
        "coverage": {
            "vendor_catalog": [
                {
                    "product_key": "edge-windows",
                    "parsed": 25,
                    "discovered": 25,
                    "unavailable_cves": [],
                }
            ]
        },
    }
    output = _software_result(source)["products"][0]
    assert len(output["matches"]) == 20 and output["matches_truncated"]
    assert output["reference_fix"] == "175.0.0.0" and output["reference_fix_complete"]
    source["coverage"]["vendor_catalog"][0]["unavailable_cves"] = ["CVE-2026-0001"]
    output = _software_result(source)["products"][0]
    assert output["reference_fix"] == "175.0.0.0" and output["reference_fix_complete"]
    assert _software_result(source)["coverage"]["vendor_catalog"][0]["unavailable_count"] == 1


def test_reference_fix_handles_curated_7zip_zero_lower_bound():
    from app.api.v1.host_overview import _reference_fix

    product = {
        "product_key": "7zip-windows",
        "version": "24.09",
        "matches_total": 1,
        "matches_truncated": False,
        "matches": [{"affected_ranges": [{"introduced": "0", "fixed": "25.01"}]}],
    }
    assert _reference_fix(product) == ("25.01", True)


def test_new_malformed_retained_inventory_does_not_fall_back_to_an_older_good_status(
    secured, customer, db
):
    snapshots(db)
    first = run(
        db, customer["id"], evidence=inventory(), created=datetime.now(UTC) - timedelta(hours=1)
    )
    assess_windows(first.id, None, db)
    latest = run(
        db,
        customer["id"],
        evidence={"schema_version": 1, "os": None},
        existing_asset=db.get(Asset, first.asset_id),
    )
    host = get(secured, customer["id"])["hosts"][0]
    assert host["latest_run"]["id"] == latest.id
    assert host["inventory"] is None and host["windows_assessment"] is None
    assert host["platform"] == "unclassified" and "inventory_missing" in host["issues"]
