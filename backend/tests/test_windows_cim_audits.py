"""CIM evidence keeps existing authorization and never implies patch coverage."""

import copy
from datetime import UTC, datetime

import pytest
from test_host_audits import FINGERPRINT, PASSWORD, credential
from test_host_audits import db as db
from test_host_audits import secured as secured

from app.models.host_assessment import HostAssessment
from app.models.host_audit import HostAudit
from app.models.job import Job
from app.models.software_assessment import SoftwareAssessment
from app.services import audit_vault, host_inventory
from app.services.software_assessment import assess_software
from app.services.windows_patch_assessment import assess_windows_patches
from app.services.windows_update_assessment import assess_windows_updates
from app.worker.main import claim_next_job, process_job


def evidence(mode="cim_inventory", *, qfe_status="complete"):
    return {
        "schema_version": 1,
        "collection_method": "cim",
        "os": {
            "family": "Windows",
            "name": "Microsoft Windows 11 Pro",
            "version": "10.0.26300",
            "kernel": "26300",
            "architecture": "64-bit",
            "hostname": "CIM-FIXTURE",
            "product_type": "1",
            "sku": "48",
        },
        "packages": {"status": "not_requested", "source": "none", "items": []},
        "hotfixes": {
            "status": "not_requested" if mode == "cim_connection" else qfe_status,
            "source": "Win32_QuickFixEngineering",
            "items": (
                [{"id": "KB5000001", "description": "Synthetic security update"}]
                if mode == "cim_inventory" and qfe_status in {"complete", "truncated"}
                else []
            ),
        },
    }


def start(secured, customer, *, mode="cim_inventory", kind="winrm", **changes):
    cred = credential(secured, customer, kind=kind)
    payload = {
        "customer_id": customer["id"],
        "credential_id": cred["id"],
        "target": "192.0.2.1",
        "mode": mode,
        "winrm_transport": "http_ntlm",
        **changes,
    }
    return secured.post("/api/v1/host-audits", json=payload)


@pytest.mark.parametrize("mode", ["cim_connection", "cim_inventory"])
@pytest.mark.parametrize("transport,port", [("https", 5986), ("http_ntlm", 5985)])
def test_cim_requests_preserve_selected_encrypted_transport(
    secured, customer, db, mode, transport, port
):
    response = start(secured, customer, mode=mode, winrm_transport=transport)
    assert response.status_code == 201, response.text
    run = response.json()
    assert run["mode"] == mode and run["port"] == port
    assert run["winrm_transport"] == transport
    assert "CIM" in run["job"]["message"]
    assert PASSWORD not in response.text
    audit = db.get(HostAudit, run["id"])
    assert audit.scope_sha256 == audit_vault.audit_hash(audit, audit.credential)


@pytest.mark.parametrize("mode", ["cim_connection", "cim_inventory"])
def test_cim_is_not_available_for_ssh_credentials(secured, customer, db, mode):
    response = start(
        secured,
        customer,
        mode=mode,
        kind="ssh_password",
        winrm_transport="https",
        ssh_fingerprint=FINGERPRINT,
    )
    assert response.status_code == 422
    assert db.query(Job).count() == 0


@pytest.mark.parametrize("change", ["revoked", "scope", "customer"])
def test_cim_does_not_bypass_credential_authorization(secured, customer, db, change):
    cred = credential(secured, customer, kind="winrm")
    payload = {
        "customer_id": customer["id"],
        "credential_id": cred["id"],
        "target": "192.0.2.1",
        "mode": "cim_inventory",
    }
    if change == "revoked":
        assert (
            secured.post(f"/api/v1/host-audits/credentials/{cred['id']}/revoke").status_code == 200
        )
    elif change == "scope":
        payload["target"] = "192.0.2.30"
    else:
        other = secured.post("/api/v1/customers", json={"name": "Other CIM customer"}).json()
        payload["customer_id"] = other["id"]
    response = secured.post("/api/v1/host-audits", json=payload)
    assert response.status_code == 422
    assert db.query(Job).count() == 0


def test_cim_and_shell_audits_share_the_same_active_host_lock(secured, customer):
    first = start(secured, customer)
    assert first.status_code == 201
    assert start(secured, customer, mode="cim_connection").status_code == 409
    assert start(secured, customer, mode="inventory").status_code == 409


@pytest.mark.parametrize("mode", ["cim_connection", "cim_inventory"])
def test_cim_worker_retains_limited_evidence_without_software_or_patch_claims(
    secured, customer, db, monkeypatch, mode
):
    response = start(secured, customer, mode=mode)
    assert response.status_code == 201
    audit = db.get(HostAudit, response.json()["id"])

    def collect(payload, cancelled):
        assert payload["kind"] == "winrm" and payload["mode"] == mode
        assert payload["winrm_transport"] == "http_ntlm"
        assert payload["username"] == "inventory"
        assert payload["secrets"] == {"password": PASSWORD}
        assert not cancelled()
        return evidence(mode)

    monkeypatch.setattr(host_inventory, "collect", collect)
    process_job(db, claim_next_job(db))
    detail = secured.get(f"/api/v1/host-audits/{audit.id}").json()
    assert detail["job"]["status"] == "finished"
    assert detail["job"]["progress"] == 100
    assert "CIM" in detail["job"]["message"]
    assert detail["inventory"] == evidence(mode)
    assert detail["inventory"]["os"]["kernel"] == "26300"
    assert not set(detail["inventory"]["os"]) & {
        "edition_id",
        "installation_type",
        "native_architecture",
    }
    assert PASSWORD not in detail["job"]["message"]
    assert db.query(HostAssessment).count() == db.query(SoftwareAssessment).count() == 0


@pytest.mark.parametrize("qfe_status", ["unavailable", "truncated"])
def test_qfe_failure_or_truncation_retains_os_without_marking_complete(
    secured, customer, db, monkeypatch, qfe_status
):
    response = start(secured, customer)
    assert response.status_code == 201
    data = evidence(qfe_status=qfe_status)
    monkeypatch.setattr(host_inventory, "collect", lambda *args, **kwargs: data)
    process_job(db, claim_next_job(db))
    audit = db.get(HostAudit, response.json()["id"])
    assert audit.job.status == "failed"
    assert audit.inventory["os"]["hostname"] == "CIM-FIXTURE"
    assert audit.inventory["hotfixes"]["status"] == qfe_status
    assert audit.inventory["packages"]["status"] == "not_requested"


@pytest.mark.parametrize("replacement", ["inventory", "cim_connection", "windows_updates"])
def test_cim_mode_cannot_be_changed_to_trigger_a_shell_after_queueing(
    secured, customer, db, monkeypatch, replacement
):
    response = start(secured, customer)
    assert response.status_code == 201
    audit = db.get(HostAudit, response.json()["id"])
    audit.mode = replacement
    db.commit()
    monkeypatch.setattr(
        host_inventory, "collect", lambda *a, **kw: pytest.fail("must not authenticate")
    )
    process_job(db, claim_next_job(db))
    assert audit.job.status == "failed" and audit.inventory is None


def test_cancelled_cim_queue_never_authenticates(secured, customer, db):
    response = start(secured, customer)
    assert response.status_code == 201
    run = response.json()
    cancelled = secured.post(f"/api/v1/host-audits/{run['id']}/cancel")
    assert cancelled.json()["job"]["status"] == "cancelled"
    assert claim_next_job(db) is None


def test_worker_rejects_cim_for_ssh_even_with_a_valid_recomputed_hash(
    secured, customer, db, monkeypatch
):
    response = start(
        secured,
        customer,
        mode="inventory",
        kind="ssh_password",
        winrm_transport="https",
        ssh_fingerprint=FINGERPRINT,
    )
    assert response.status_code == 201
    audit = db.get(HostAudit, response.json()["id"])
    audit.mode = "cim_inventory"
    audit.scope_sha256 = audit_vault.audit_hash(audit, audit.credential)
    db.commit()
    monkeypatch.setattr(
        host_inventory, "collect", lambda *a, **kw: pytest.fail("must not authenticate")
    )
    process_job(db, claim_next_job(db))
    assert audit.job.status == "failed" and audit.inventory is None


def test_revocation_during_cim_collection_discards_new_evidence(secured, customer, db, monkeypatch):
    response = start(secured, customer)
    assert response.status_code == 201
    run = response.json()

    def collect(payload, cancelled):
        revoked = secured.post(f"/api/v1/host-audits/credentials/{run['credential_id']}/revoke")
        assert revoked.status_code == 200 and cancelled()
        return evidence()

    monkeypatch.setattr(host_inventory, "collect", collect)
    process_job(db, claim_next_job(db))
    audit = db.get(HostAudit, run["id"])
    assert audit.job.status == "cancelled" and audit.inventory is None


@pytest.mark.parametrize("mode", ["cim_connection", "cim_inventory"])
def test_cim_normalizer_retains_only_explicit_limited_evidence(mode):
    data = evidence(mode)
    assert host_inventory.normalize_inventory(data, "winrm", mode) == data


@pytest.mark.parametrize(
    "change",
    [
        "missing_provider",
        "wrong_provider",
        "software_source",
        "software_status",
        "software_row",
        "wua",
        "invented_ubr",
        "invented_edition",
        "invented_architecture",
        "wrong_qfe_source",
    ],
)
def test_cim_normalizer_rejects_forged_collection_or_unread_evidence(change):
    data = evidence()
    if change == "missing_provider":
        del data["collection_method"]
    elif change == "wrong_provider":
        data["collection_method"] = "winrs"
    elif change == "software_source":
        data["packages"]["source"] = "registry-uninstall"
    elif change == "software_status":
        data["packages"]["status"] = "complete"
    elif change == "software_row":
        data["packages"]["items"] = [{"name": "Fake", "version": "1", "architecture": "x64"}]
    elif change == "wua":
        data["windows_updates"] = {}
    elif change == "invented_ubr":
        data["os"]["kernel"] = "26300.0"
    elif change == "invented_edition":
        data["os"]["edition_id"] = "Professional"
    elif change == "invented_architecture":
        data["os"]["native_architecture"] = "AMD64"
    else:
        data["hotfixes"]["source"] = "Get-HotFix"
    with pytest.raises(host_inventory.CollectionError):
        host_inventory.normalize_inventory(data, "winrm", "cim_inventory")


@pytest.mark.parametrize("mode", ["connection", "inventory", "windows_updates"])
def test_cim_provider_cannot_be_attached_to_a_legacy_shell_run(mode):
    with pytest.raises(host_inventory.CollectionError):
        host_inventory.normalize_inventory(evidence(), "winrm", mode)


@pytest.mark.parametrize("kind", ["ssh_password", "ssh_key"])
def test_cim_normalizer_requires_a_windows_credential_kind(kind):
    with pytest.raises(host_inventory.CollectionError):
        host_inventory.normalize_inventory(evidence(), kind, "cim_inventory")


def test_cim_connection_cannot_claim_hotfix_enumeration():
    with pytest.raises(host_inventory.CollectionError):
        host_inventory.normalize_inventory(evidence(), "winrm", "cim_connection")


def test_cim_hotfix_rows_do_not_establish_software_or_patch_coverage():
    now = datetime.now(UTC)
    data = evidence()
    original = copy.deepcopy(data)
    result = assess_windows_updates(
        data, evidence_collected_at=now, now=now, evidence_mode="cim_inventory"
    )
    assert result["status"] == "update_query_required" and result["windows_updates"] is None
    software = assess_software(data, None, evidence_collected_at=now, now=now)
    assert software["status"] == "unsupported"
    server = copy.deepcopy(data)
    server["os"].update(
        name="Microsoft Windows Server 2022 Datacenter",
        version="10.0.20348",
        kernel="20348",
        product_type="3",
    )
    baseline = assess_windows_patches(server, None, evidence_collected_at=now, now=now)
    assert baseline["status"] == "identity_incomplete"
    assert data == original


def test_cim_audit_does_not_accept_patch_or_software_assessment_actions(
    secured, customer, db, monkeypatch
):
    response = start(secured, customer)
    assert response.status_code == 201
    monkeypatch.setattr(host_inventory, "collect", lambda *args, **kwargs: evidence())
    process_job(db, claim_next_job(db))
    audit_id = response.json()["id"]
    assert secured.post(f"/api/v1/host-audits/{audit_id}/assess").status_code == 422
    assert secured.post(f"/api/v1/host-audits/{audit_id}/assess-software").status_code == 422
    assert db.query(HostAssessment).count() == db.query(SoftwareAssessment).count() == 0
