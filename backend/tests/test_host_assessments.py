"""Protected assessment persistence, independent of catalog/parser engine unit tests."""

import base64
import copy
import json
import sys
from datetime import UTC, datetime, timedelta
from types import ModuleType

import httpx
import pytest

from app.api.v1 import host_assessments as api
from app.database.deps import get_db
from app.main import app
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.host_assessment import HostAssessment, WindowsPatchCatalog
from app.models.host_audit import HostAudit
from app.models.job import Job
from app.services import audit_vault, host_inventory, windows_patch_sync

TOKEN = "synthetic-assessment-operator-token-only"
PASSWORD = "synthetic-assessment-account-password"
NOW = datetime(2026, 11, 7, 9, tzinfo=UTC)


@pytest.fixture
def secured(client, monkeypatch):
    monkeypatch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"k" * 32).decode())
    monkeypatch.setenv("CCVM_AUDIT_OPERATOR_TOKEN", TOKEN)
    monkeypatch.setenv("CCVM_NETWORK_ALLOWED_CIDRS", "192.0.2.0/24")
    client.base_url = httpx.URL("https://testserver")
    client.headers["Authorization"] = f"Bearer {TOKEN}"
    return client


@pytest.fixture
def db(client):
    return next(app.dependency_overrides[get_db]())


@pytest.fixture
def engine(monkeypatch):
    module = ModuleType("app.services.windows_patch_assessment")
    module.ENGINE_VERSION = "synthetic-assessment-v1"
    calls = []

    def assess(inventory, catalog, *, evidence_collected_at, now):
        calls.append(copy.deepcopy((inventory, catalog, evidence_collected_at, now)))
        # A misbehaving engine must not mutate stored source evidence.
        inventory["os"]["hostname"] = "mutated-local-copy"
        return {
            "schema_version": 1,
            "status": "build_gap" if catalog else "catalog_unavailable",
            "evaluated_at": now.isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat() if catalog else None,
            "reason": "Synthetic local assessment",
            "baseline_build": "10.0.20348.99" if catalog else None,
        }

    module.assess_windows_patches = assess
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return calls


@pytest.fixture
def completed(secured, customer, db):
    response = secured.post(
        "/api/v1/host-audits/credentials",
        json={
            "customer_id": customer["id"],
            "name": "Windows fixture",
            "kind": "winrm",
            "username": "EXAMPLE\\inventory",
            "password": PASSWORD,
            "allowed_cidrs": ["192.0.2.0/24"],
        },
    )
    assert response.status_code == 201
    run = secured.post(
        "/api/v1/host-audits",
        json={
            "customer_id": customer["id"],
            "credential_id": response.json()["id"],
            "target": "192.0.2.1",
            "winrm_transport": "http_ntlm",
        },
    )
    assert run.status_code == 201
    audit = db.get(HostAudit, run.json()["id"])
    audit.inventory = {
        "schema_version": 1,
        "os": {
            "family": "Windows",
            "name": "Windows Server 2022 Standard",
            "hostname": "synthetic-host",
            "kernel": "20348.1",
        },
        "packages": {"status": "complete", "source": "registry-uninstall", "items": []},
        "hotfixes": {"status": "complete", "source": "Get-HotFix", "items": []},
    }
    audit.completed_at = datetime.now(UTC)
    audit.job.status, audit.job.progress = "finished", 100
    db.commit()
    return audit


def seed_catalog(db, monkeypatch, *, retrieved=None):
    retrieved = retrieved or datetime.now(UTC)
    payload = {
        "schema_version": 1,
        "source": "msrc-cvrf",
        "retrieved_at": retrieved.isoformat(),
        "coverage_start": "2026-09-01",
        "coverage_end": "2026-11-07",
        "documents": [{"id": "2026-Oct"}],
        "entries": [{"cve": "CVE-2026-0001"}],
    }
    # Parser validation has its own raw/normalized fixture suite. These tests
    # isolate API integrity, access and immutable persistence from the engine.
    monkeypatch.setattr(api, "validated_catalog", copy.deepcopy)
    row = WindowsPatchCatalog(
        source=payload["source"],
        sha256=windows_patch_sync.catalog_digest(payload),
        payload=payload,
        retrieved_at=retrieved,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@pytest.mark.parametrize("path", ["/patch-catalog", "/1/assessments", "/1/assess"])
def test_assessment_paths_require_tls_and_operator(secured, path):
    request = secured.post if path.endswith("/assess") else secured.get
    full = "/api/v1/host-audits" + path
    assert request(full, headers={"Authorization": "Bearer invalid"}).status_code == 401
    secured.base_url = httpx.URL("http://testserver")
    response = request(full, headers={"X-Forwarded-Proto": "https"})
    assert response.status_code == 403
    assert response.headers["cache-control"] == "no-store"


def test_catalog_metadata_static_route_precedes_dynamic_audit_route(secured, db, monkeypatch):
    assert secured.get("/api/v1/host-audits/patch-catalog").json() is None
    row = seed_catalog(db, monkeypatch)
    response = secured.get("/api/v1/host-audits/patch-catalog")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == row.id and data["entry_count"] == 1
    assert data["document_ids"] == ["2026-Oct"]
    assert "payload" not in data and "CVE-2026-0001" not in response.text


def test_assessment_is_local_idempotent_and_does_not_mutate_evidence(
    secured, db, completed, monkeypatch, engine
):
    seed_catalog(db, monkeypatch)
    before = copy.deepcopy(completed.inventory)
    job_count, finding_count = db.query(Job).count(), db.query(Finding).count()

    def forbidden(*_args, **_kwargs):
        pytest.fail("Assessment must not authenticate, decrypt or collect a host")

    monkeypatch.setattr(audit_vault, "decrypt", forbidden)
    monkeypatch.setattr(host_inventory, "collect", forbidden)
    path = f"/api/v1/host-audits/{completed.id}/assess"
    first = secured.post(path, json={})
    second = secured.post(path)
    assert first.status_code == second.status_code == 200
    assert first.json()["id"] == second.json()["id"]
    assert first.json()["status"] == "build_gap" and not first.json()["expired"]
    assert len(engine) == 1 and db.query(HostAssessment).count() == 1
    db.refresh(completed)
    assert completed.inventory == before
    assert db.query(Job).count() == job_count and db.query(Finding).count() == finding_count
    assert PASSWORD not in first.text and TOKEN not in first.text
    assert "username" not in first.text and "ciphertext" not in first.text
    history = secured.get(f"/api/v1/host-audits/{completed.id}/assessments")
    assert history.json()[0]["id"] == first.json()["id"]
    assert history.headers["cache-control"] == "no-store"


def test_missing_catalog_is_explicit_and_null_catalog_is_idempotent(secured, db, completed, engine):
    path = f"/api/v1/host-audits/{completed.id}/assess"
    first, second = secured.post(path, json={}), secured.post(path, json={})
    assert first.status_code == 200
    assert first.json()["status"] == "catalog_unavailable"
    assert first.json()["catalog_id"] is None and first.json()["expired"]
    assert first.json()["id"] == second.json()["id"]
    assert db.query(HostAssessment).count() == 1


def test_expired_assessment_remains_immutable_and_is_never_returned_as_current(
    secured, db, completed, monkeypatch, engine
):
    seed_catalog(db, monkeypatch)
    path = f"/api/v1/host-audits/{completed.id}/assess"
    first = secured.post(path).json()
    row = db.get(HostAssessment, first["id"])
    saved = {**row.result, "valid_until": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()}
    row.result = saved
    db.commit()
    second = secured.post(path).json()
    assert second["id"] == row.id and second["expired"]
    assert second["result"] == saved and len(engine) == 1


@pytest.mark.parametrize("change", ["running", "connection", "missing_evidence", "missing_date"])
def test_incomplete_or_connection_runs_are_not_assessed(secured, db, completed, change, engine):
    if change == "running":
        completed.job.status = "running"
    elif change == "connection":
        completed.mode = "connection"
    elif change == "missing_evidence":
        completed.inventory = None
    else:
        completed.completed_at = None
    db.commit()
    response = secured.post(f"/api/v1/host-audits/{completed.id}/assess", json={})
    assert response.status_code == 422 and not engine
    assert db.query(HostAssessment).count() == 0


def test_asset_customer_identity_is_rechecked_without_credentials(secured, db, completed, engine):
    other = secured.post("/api/v1/customers", json={"name": "Other customer"}).json()
    asset = db.get(Asset, completed.asset_id)
    asset.customer_id = other["id"]
    db.commit()
    assert secured.post(f"/api/v1/host-audits/{completed.id}/assess").status_code == 409
    assert secured.get(f"/api/v1/host-audits/{completed.id}/assessments").status_code == 409
    assert not engine


def test_catalog_corruption_is_not_assessed_or_exposed(secured, db, completed, monkeypatch, engine):
    catalog = seed_catalog(db, monkeypatch)
    catalog.sha256 = "0" * 64
    db.commit()
    response = secured.post(f"/api/v1/host-audits/{completed.id}/assess")
    assert response.status_code == 503 and not engine
    assert response.json()["detail"] == "Stored patch catalog failed validation"
    assert db.query(HostAssessment).count() == 0


def test_invalid_request_does_not_echo_secrets(secured, completed, engine):
    response = secured.post(
        f"/api/v1/host-audits/{completed.id}/assess", json={"password": PASSWORD}
    )
    assert response.status_code == 422 and PASSWORD not in response.text
    assert not engine


def test_catalog_store_is_atomic_on_fetch_and_validation_failure(db, monkeypatch):
    module = ModuleType("app.services.windows_patch_catalog")

    def broken_fetch(**kwargs):
        raise ValueError("synthetic incomplete upstream source")

    module.fetch_catalog = broken_fetch
    monkeypatch.setitem(sys.modules, module.__name__, module)
    with pytest.raises(ValueError):
        windows_patch_sync.synchronize_catalog(db)
    assert db.query(WindowsPatchCatalog).count() == 0
    monkeypatch.setattr(
        windows_patch_sync, "validated_catalog", lambda _: (_ for _ in ()).throw(ValueError())
    )
    with pytest.raises(ValueError):
        windows_patch_sync.store_catalog(db, {})
    assert db.query(WindowsPatchCatalog).count() == 0


def test_catalog_store_uses_canonical_snapshot_identity(db, monkeypatch):
    monkeypatch.setattr(windows_patch_sync, "validated_catalog", copy.deepcopy)
    payload = {"source": "msrc-cvrf", "retrieved_at": NOW.isoformat(), "documents": []}
    first = windows_patch_sync.store_catalog(db, payload)
    second = windows_patch_sync.store_catalog(db, json.loads(json.dumps(payload)))
    assert first.id == second.id and db.query(WindowsPatchCatalog).count() == 1


def test_real_catalog_engine_and_protected_api_roundtrip(secured, db, completed):
    now = datetime.now(UTC)
    first = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    document_id = first.strftime("%Y-%b")
    payload = {
        "schema_version": 1,
        "source": "msrc-cvrf",
        "retrieved_at": now.isoformat(),
        "coverage_start": first.date().isoformat(),
        "coverage_end": now.date().isoformat(),
        "documents": [
            {
                "id": document_id,
                "url": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/" + document_id,
                "sha256": "a" * 64,
                "initial_release_date": first.isoformat(),
                "current_release_date": first.isoformat(),
            }
        ],
        "entries": [
            {
                "product_id": "11923",
                "product_name": "Windows Server 2022",
                "cve": "CVE-2026-00001",
                "title": "Synthetic baseline reference",
                "severity": "high",
                "kb": "KB5126655",
                "fixed_build": "10.0.20348.99",
                "document_id": document_id,
                "source_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-00001",
                "subtype": "Security Update",
            }
        ],
    }
    catalog = windows_patch_sync.store_catalog(db, payload)
    original = copy.deepcopy(completed.inventory)
    original["os"].update(
        version="10.0.20348",
        architecture="64-bit",
        product_type="3",
        installation_type="Server",
        edition_id="ServerStandard",
        native_architecture="AMD64",
    )
    completed.inventory = original
    db.commit()
    response = secured.post(f"/api/v1/host-audits/{completed.id}/assess", json={})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["catalog_id"] == catalog.id
    assert data["status"] == "build_gap" and not data["expired"]
    assert data["result"]["baseline_build"] == "10.0.20348.99"
    assert data["result"]["cve_references"][0]["cve"] == "CVE-2026-00001"
    assert data["result"]["coverage"]["component_applicability"] == "not_checked"
    db.refresh(completed)
    assert completed.inventory == original
