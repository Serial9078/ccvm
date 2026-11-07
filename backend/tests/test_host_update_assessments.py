"""WUA assessments stay private, evidence-bound and independent of MSRC snapshots."""

# Shared pytest fixtures are imported intentionally.
# ruff: noqa: F811

import copy
from datetime import UTC, datetime, timedelta

import pytest
from test_host_assessments import completed, db, secured  # noqa: F401
from test_host_overview import get, inventory, run, snapshots
from test_windows_update_assessment import evidence, offer

from app.api.v1 import host_assessments
from app.models.finding import Finding
from app.models.host_assessment import HostAssessment
from app.models.job import Job
from app.services import audit_vault, host_inventory
from app.services.windows_update_assessment import ENGINE_VERSION


def client_inventory(items=None):
    data = inventory(product_type="1")
    data["os"].update(
        name="Microsoft Windows 11 Pro",
        version="10.0.26200",
        kernel="26200.9711",
        installation_type="Client",
        edition_id="Professional",
    )
    data["windows_updates"] = evidence(items)["windows_updates"]
    data["windows_updates"]["queried_at"] = (datetime.now(UTC) - timedelta(minutes=2)).isoformat()
    return data


def test_client_assessment_is_local_idempotent_private_and_catalog_independent(
    secured,
    completed,
    db,
    monkeypatch,
):
    completed.mode = "windows_updates"
    completed.inventory = client_inventory()
    db.commit()
    before = copy.deepcopy(completed.inventory)
    jobs, findings = db.query(Job).count(), db.query(Finding).count()

    def forbidden(*_args, **_kwargs):
        pytest.fail(
            "Client offer assessment must not collect, decrypt or validate a Server catalog"
        )

    monkeypatch.setattr(host_inventory, "collect", forbidden)
    monkeypatch.setattr(audit_vault, "decrypt", forbidden)
    monkeypatch.setattr(host_assessments, "checked_catalog", forbidden)
    path = f"/api/v1/host-audits/{completed.id}/assess"
    first, second = secured.post(path), secured.post(path)
    assert first.status_code == second.status_code == 200
    result = first.json()
    assert result["id"] == second.json()["id"]
    assert result["status"] == "updates_offered" and result["engine_version"] == ENGINE_VERSION
    assert result["provider"] == "windows-update-agent" and result["catalog_applicable"] is False
    assert result["catalog_id"] is None and not result["expired"]
    assert db.query(HostAssessment).count() == 1
    db.refresh(completed)
    assert completed.inventory == before
    assert db.query(Job).count() == jobs and db.query(Finding).count() == findings
    assert (
        "username" not in first.text
        and "password" not in first.text
        and "ciphertext" not in first.text
    )
    history = secured.get(f"/api/v1/host-audits/{completed.id}/assessments")
    assert history.json()[0]["provider"] == "windows-update-agent"
    assert history.headers["cache-control"] == "no-store"


def test_normal_client_inventory_requires_explicit_online_collection(secured, completed, db):
    completed.inventory = client_inventory([])
    db.commit()
    response = secured.post(f"/api/v1/host-audits/{completed.id}/assess")
    assert response.status_code == 200
    assert response.json()["status"] == "update_query_required"
    assert response.json()["expired"]
    assert response.json()["result"]["windows_updates"] is None


def test_client_offer_overview_has_no_catalog_claim_and_is_compact(secured, customer, db):
    snapshots(db)
    audit = run(
        db,
        customer["id"],
        evidence=client_inventory([offer(i) for i in range(25)]),
        mode="windows_updates",
    )
    result = host_assessments.create_assessment(audit.id, None, db)
    data = get(secured, customer["id"])
    host = data["hosts"][0]
    patch = host["windows_assessment"]
    assert host["platform"] == "windows_client"
    assert host["inventory"]["mode"] == "windows_updates"
    assert host["inventory"]["windows_updates"]["has_evidence"]
    assert patch["id"] == result["id"] and patch["provider"] == "windows-update-agent"
    assert patch["source"] == "configured_windows_update_service"
    assert patch["catalog_applicable"] is False and patch["current_catalog"] is False
    assert patch["evidence_matches"] and patch["engine_current"] and not patch["expired"]
    assert patch["result"]["windows_updates"]["summary"]["offers"] == 25
    assert len(patch["result"]["windows_updates"]["items"]) == 20
    assert patch["result"]["windows_updates"]["items_truncated"]
    assert "cve_references" not in patch["result"]
    assert "windows_client_patch_coverage_unavailable" not in host["issues"]
    assert "windows_client_update_query_required" not in host["issues"]


def test_no_offer_status_stays_neutral_and_report_expiry_uses_24_hours(secured, customer, db):
    audit = run(db, customer["id"], evidence=client_inventory([]), mode="windows_updates")
    row = host_assessments.create_assessment(audit.id, None, db)
    host = get(secured, customer["id"])["hosts"][0]
    assert host["windows_assessment"]["status"] == "no_update_offers"
    assert "fully patched" in host["windows_assessment"]["result"]["reason"]
    assessment = db.get(HostAssessment, row["id"])
    assessment.evaluated_at = datetime.now(UTC) - timedelta(hours=24)
    db.commit()
    assert get(secured, customer["id"])["hosts"][0]["windows_assessment"]["expired"]


def test_newer_normal_inventory_does_not_reuse_old_wua_evidence(secured, customer, db):
    first = run(
        db,
        customer["id"],
        evidence=client_inventory(),
        mode="windows_updates",
        created=datetime.now(UTC) - timedelta(hours=1),
    )
    host_assessments.create_assessment(first.id, None, db)
    newer = client_inventory()
    del newer["windows_updates"]
    second = run(
        db,
        customer["id"],
        evidence=newer,
        existing_asset=first.job.asset,
        created=datetime.now(UTC) - timedelta(seconds=30),
    )
    host = get(secured, customer["id"])["hosts"][0]
    assert host["inventory"]["id"] == second.id
    assert host["windows_assessment"] is None
    assert "windows_client_update_query_required" in host["issues"]


def test_wua_evidence_hash_change_is_visible_without_reassessment(secured, customer, db):
    audit = run(db, customer["id"], evidence=client_inventory(), mode="windows_updates")
    host_assessments.create_assessment(audit.id, None, db)
    changed = copy.deepcopy(audit.inventory)
    changed["windows_updates"]["items"][0]["title"] = "Changed retained evidence"
    audit.inventory = changed
    db.commit()
    patch = get(secured, customer["id"])["hosts"][0]["windows_assessment"]
    assert not patch["evidence_matches"]


def test_wua_mode_inventory_remains_eligible_for_saved_software_assessment(secured, customer, db):
    from app.api.v1.software_assessments import create_assessment

    snapshots(db)
    audit = run(db, customer["id"], evidence=client_inventory(), mode="windows_updates")
    assert create_assessment(audit.id, None, db)["host_audit_id"] == audit.id
