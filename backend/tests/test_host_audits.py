import base64
import copy
import hashlib
import json
import subprocess
from types import SimpleNamespace

import httpx
import pytest

from app.database.deps import get_db
from app.main import app
from app.models.host_audit import AuditCredential, HostAudit
from app.models.job import Job
from app.services import audit_vault, host_audit_transport, host_inventory
from app.services.network_rules import coverage_for
from app.worker.main import claim_next_job, process_job

TOKEN = "synthetic-operator-token-for-unit-tests-only"
PASSWORD = "synthetic password never returned by the API"
FINGERPRINT = "SHA256:" + "A" * 43


@pytest.fixture
def secured(client, monkeypatch):
    monkeypatch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"k" * 32).decode())
    monkeypatch.setenv("CCVM_AUDIT_OPERATOR_TOKEN", TOKEN)
    monkeypatch.setenv("CCVM_NETWORK_ALLOWED_CIDRS", "192.0.2.0/24,2001:db8::/120")
    client.base_url = httpx.URL("https://testserver")
    client.headers["Authorization"] = f"Bearer {TOKEN}"
    return client


@pytest.fixture
def db(client):
    return next(app.dependency_overrides[get_db]())


def credential_payload(customer, **changes):
    return {
        "customer_id": customer["id"],
        "name": "Linux lab",
        "kind": "ssh_password",
        "username": "inventory",
        "password": PASSWORD,
        "allowed_cidrs": ["192.0.2.0/28"],
        **changes,
    }


def credential(secured, customer, **changes):
    response = secured.post(
        "/api/v1/host-audits/credentials", json=credential_payload(customer, **changes)
    )
    assert response.status_code == 201, response.text
    assert PASSWORD not in response.text
    assert "ciphertext" not in response.text
    assert "private_key" not in response.text
    return response.json()


def queued(secured, customer, **changes):
    cred = credential(secured, customer)
    response = secured.post(
        "/api/v1/host-audits",
        json={
            "customer_id": customer["id"],
            "credential_id": cred["id"],
            "target": "192.0.2.1",
            "ssh_fingerprint": FINGERPRINT,
            **changes,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def inventory(family="Linux", mode="inventory"):
    return {
        "schema_version": 1,
        "os": {
            "family": family,
            "name": "Fixture OS",
            "version": "1",
            "kernel": "1.2",
            "architecture": "amd64",
            "hostname": "lab",
        },
        "packages": {
            "status": "complete" if mode == "inventory" else "not_requested",
            "source": "dpkg" if family == "Linux" else "registry-uninstall",
            "items": (
                [
                    {
                        "name": "fixture-package",
                        "version": "1:2.0-3",
                        "architecture": "amd64",
                    }
                ]
                if mode == "inventory"
                else []
            ),
        },
        "hotfixes": {
            "status": (
                "not_applicable"
                if family == "Linux"
                else "complete" if mode == "inventory" else "not_requested"
            ),
            "source": "none" if family == "Linux" else "Get-HotFix",
            "items": [],
        },
    }


def test_tls_token_and_configuration_are_required(secured, customer, monkeypatch):
    path = f"/api/v1/host-audits/credentials?customer_id={customer['id']}"
    assert secured.get(path).status_code == 200
    secured.base_url = httpx.URL("http://testserver")
    assert secured.get(path, headers={"X-Forwarded-Proto": "https"}).status_code == 403
    secured.base_url = httpx.URL("https://testserver")
    assert secured.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert secured.get(path, headers={b"Authorization": b"Bearer \xc3\xa4"}).status_code == 401
    monkeypatch.delenv("CCVM_AUDIT_VAULT_KEY")
    response = secured.get(path)
    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "changes",
    [
        {"allowed_cidrs": ["198.51.100.0/24"]},
        {"allowed_cidrs": ["192.0.0.0/16"]},
        {"allowed_cidrs": []},
        {"private_key": PASSWORD},
        {"password": ""},
        {"password": PASSWORD * 1000},
        {"kind": "basic"},
        {"username": "x\npassword"},
        {"extra_secret": PASSWORD},
        {"kind": "ssh_key", "password": None},
    ],
)
def test_invalid_credentials_do_not_echo_secrets(secured, customer, changes):
    response = secured.post(
        "/api/v1/host-audits/credentials", json=credential_payload(customer, **changes)
    )
    assert response.status_code == 422
    assert PASSWORD not in response.text
    assert all(
        "input" not in item for item in response.json().get("detail", []) if isinstance(item, dict)
    )


def test_vault_encrypts_and_authenticates_metadata(secured, customer, db):
    first = credential(secured, customer)
    second = credential(secured, customer)
    row = db.get(AuditCredential, first["id"])
    assert PASSWORD.encode() not in row.ciphertext
    assert row.ciphertext != db.get(AuditCredential, second["id"]).ciphertext
    assert audit_vault.decrypt(row) == {"password": PASSWORD}
    for attribute, value in (
        ("customer_id", 99),
        ("username", "other"),
        ("kind", "winrm"),
        ("allowed_cidrs", ["192.0.2.0/24"]),
        ("uuid", second["uuid"]),
    ):
        old = getattr(row, attribute)
        setattr(row, attribute, value)
        with pytest.raises(ValueError, match="cannot be decrypted"):
            audit_vault.decrypt(row)
        setattr(row, attribute, old)
    listed = secured.get(f"/api/v1/host-audits/credentials?customer_id={customer['id']}")
    assert PASSWORD not in listed.text
    assert "ciphertext" not in listed.text
    assert listed.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "target",
    ["192.0.2.16", "198.51.100.1", "example.test", "192.0.2.1/32", "fe80::1%eth0"],
)
@pytest.mark.parametrize(
    "kind,winrm_transport",
    [("ssh_password", "https"), ("winrm", "https"), ("winrm", "http_ntlm")],
)
def test_customer_and_credential_scope_before_queue(
    secured, customer, db, target, kind, winrm_transport
):
    cred = credential(secured, customer, kind=kind)
    response = secured.post(
        "/api/v1/host-audits",
        json={
            "customer_id": customer["id"],
            "credential_id": cred["id"],
            "target": target,
            "winrm_transport": winrm_transport,
            **({"ssh_fingerprint": FINGERPRINT} if kind.startswith("ssh_") else {}),
        },
    )
    assert response.status_code == 422
    assert db.query(HostAudit).count() == db.query(Job).count() == 0


def test_cross_customer_key_change_fingerprint_and_duplicate_guards(
    secured, customer, db, monkeypatch
):
    cred = credential(secured, customer)
    other = secured.post("/api/v1/customers", json={"name": "Other fixture"}).json()
    payload = {
        "customer_id": other["id"],
        "credential_id": cred["id"],
        "target": "192.0.2.1",
    }
    assert "another customer" in secured.post("/api/v1/host-audits", json=payload).text
    payload["customer_id"] = customer["id"]
    assert "fingerprint" in secured.post("/api/v1/host-audits", json=payload).text
    payload["ssh_fingerprint"] = FINGERPRINT
    monkeypatch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"z" * 32).decode())
    assert "cannot be decrypted" in secured.post("/api/v1/host-audits", json=payload).text
    monkeypatch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"k" * 32).decode())
    assert secured.post("/api/v1/host-audits", json=payload).status_code == 201
    assert secured.post("/api/v1/host-audits", json=payload).status_code == 409
    assert db.query(Job).count() == 1
    assert (
        secured.post("/api/v1/jobs", json={"plugin": "hostinventory", "asset_id": 1}).status_code
        == 400
    )


def test_winrm_defaults_to_https_and_rejects_ssh_fingerprints(secured, customer):
    cred = credential(secured, customer, kind="winrm")
    payload = {
        "customer_id": customer["id"],
        "credential_id": cred["id"],
        "target": "192.0.2.1",
    }
    assert (
        secured.post(
            "/api/v1/host-audits", json={**payload, "ssh_fingerprint": FINGERPRINT}
        ).status_code
        == 422
    )
    response = secured.post("/api/v1/host-audits", json=payload)
    assert response.status_code == 201
    assert response.json()["port"] == 5986
    assert response.json()["winrm_transport"] == "https"


@pytest.mark.parametrize("winrm_transport,port", [("https", 5985), ("http_ntlm", 5986)])
def test_winrm_transport_is_explicit_and_not_inferred_from_port(
    secured, customer, winrm_transport, port
):
    cred = credential(secured, customer, kind="winrm")
    response = secured.post(
        "/api/v1/host-audits",
        json={
            "customer_id": customer["id"],
            "credential_id": cred["id"],
            "target": "192.0.2.1",
            "port": port,
            "winrm_transport": winrm_transport,
        },
    )
    assert response.status_code == 201
    assert response.json()["winrm_transport"] == winrm_transport
    assert response.json()["port"] == port


@pytest.mark.parametrize("winrm_transport", ["http", "basic", "auto", "", None])
def test_unrecognized_winrm_transport_does_not_queue_work(secured, customer, db, winrm_transport):
    cred = credential(secured, customer, kind="winrm")
    response = secured.post(
        "/api/v1/host-audits",
        json={
            "customer_id": customer["id"],
            "credential_id": cred["id"],
            "target": "192.0.2.1",
            "winrm_transport": winrm_transport,
        },
    )
    assert response.status_code == 422
    assert db.query(HostAudit).count() == db.query(Job).count() == 0


def test_http_winrm_transport_cannot_be_selected_for_ssh(secured, customer, db):
    cred = credential(secured, customer)
    response = secured.post(
        "/api/v1/host-audits",
        json={
            "customer_id": customer["id"],
            "credential_id": cred["id"],
            "target": "192.0.2.1",
            "ssh_fingerprint": FINGERPRINT,
            "winrm_transport": "http_ntlm",
        },
    )
    assert response.status_code == 422
    assert "Windows credentials" in response.text
    assert db.query(HostAudit).count() == db.query(Job).count() == 0


def test_http_winrm_opt_in_defaults_to_5985_and_is_retained_in_evidence(
    secured, customer, db, monkeypatch
):
    cred = credential(secured, customer, kind="winrm")
    payload = {
        "customer_id": customer["id"],
        "credential_id": cred["id"],
        "target": "192.0.2.1",
        "mode": "connection",
        "winrm_transport": "http_ntlm",
    }
    assert (
        secured.post(
            "/api/v1/host-audits", json={**payload, "ssh_fingerprint": FINGERPRINT}
        ).status_code
        == 422
    )
    response = secured.post("/api/v1/host-audits", json=payload)
    assert response.status_code == 201
    run = response.json()
    assert run["port"] == 5985 and run["winrm_transport"] == "http_ntlm"
    seen = []

    def collect(options, cancelled):
        assert not cancelled()
        seen.append(options)
        return inventory("Windows", mode="connection")

    monkeypatch.setattr(host_inventory, "collect", collect)
    process_job(db, claim_next_job(db))
    assert seen[0]["winrm_transport"] == "http_ntlm"
    assert seen[0]["port"] == 5985
    assert seen[0]["kind"] == "winrm"
    assert seen[0]["secrets"] == {"password": PASSWORD}
    detail = secured.get(f"/api/v1/host-audits/{run['id']}").json()
    assert detail["job"]["status"] == "finished"
    assert detail["winrm_transport"] == "http_ntlm"
    assert detail["inventory"]["os"]["family"] == "Windows"
    assert (
        secured.get(f"/api/v1/host-audits?customer_id={customer['id']}").json()[0][
            "winrm_transport"
        ]
        == "http_ntlm"
    )
    # Transport belongs to this run, not to the shared Windows credential.
    response = secured.post(
        "/api/v1/host-audits",
        json={key: value for key, value in payload.items() if key != "winrm_transport"},
    )
    assert response.status_code == 201
    assert response.json()["winrm_transport"] == "https" and response.json()["port"] == 5986


@pytest.mark.parametrize(
    "original,changed", [("https", "http_ntlm"), ("http_ntlm", "https"), ("https", "auto")]
)
def test_worker_rejects_changed_transport_before_authentication(
    secured, customer, db, monkeypatch, original, changed
):
    cred = credential(secured, customer, kind="winrm")
    response = secured.post(
        "/api/v1/host-audits",
        json={
            "customer_id": customer["id"],
            "credential_id": cred["id"],
            "target": "192.0.2.1",
            "winrm_transport": original,
        },
    )
    audit = db.get(HostAudit, response.json()["id"])
    audit.winrm_transport = changed
    db.commit()
    monkeypatch.setattr(
        host_inventory, "collect", lambda *a, **kw: pytest.fail("must not authenticate")
    )
    process_job(db, claim_next_job(db))
    assert audit.job.status == "failed"


def test_worker_independently_rejects_http_for_ssh_even_with_recalculated_hash(
    secured, customer, db, monkeypatch
):
    run = queued(secured, customer)
    audit = db.get(HostAudit, run["id"])
    audit.winrm_transport = "http_ntlm"
    audit.scope_sha256 = audit_vault.audit_hash(audit, audit.credential)
    db.commit()
    monkeypatch.setattr(
        host_inventory, "collect", lambda *a, **kw: pytest.fail("must not authenticate")
    )
    process_job(db, claim_next_job(db))
    assert audit.job.status == "failed" and "WinRM transport" in audit.job.message


def test_http_transport_change_during_collection_cancels_without_publishing_evidence(
    secured, customer, db, monkeypatch
):
    cred = credential(secured, customer, kind="winrm")
    response = secured.post(
        "/api/v1/host-audits",
        json={
            "customer_id": customer["id"],
            "credential_id": cred["id"],
            "target": "192.0.2.1",
            "winrm_transport": "http_ntlm",
        },
    )
    audit = db.get(HostAudit, response.json()["id"])

    def collect(payload, cancelled):
        assert payload["winrm_transport"] == "http_ntlm"
        audit.winrm_transport = "https"
        db.commit()
        assert cancelled()
        raise host_inventory.CollectionCancelled("Frozen transport changed")

    monkeypatch.setattr(host_inventory, "collect", collect)
    process_job(db, claim_next_job(db))
    assert audit.job.status == "cancelled"
    assert audit.inventory is None


@pytest.mark.parametrize("kind", ["ssh_password", "winrm"])
def test_legacy_https_and_ssh_frozen_hashes_remain_valid(secured, customer, db, kind):
    credential_row = credential(secured, customer, kind=kind)
    response = secured.post(
        "/api/v1/host-audits",
        json={
            "customer_id": customer["id"],
            "credential_id": credential_row["id"],
            "target": "192.0.2.1",
            **({"ssh_fingerprint": FINGERPRINT} if kind.startswith("ssh_") else {}),
        },
    )
    assert response.status_code == 201
    audit = db.get(HostAudit, response.json()["id"])
    cred = audit.credential
    # Original deployed v1 serialization, independent of the added DB field.
    original_hash = hashlib.sha256(
        json.dumps(
            [
                "ccvm-host-inventory-v1",
                audit.customer_id,
                audit.asset_id,
                audit.job_id,
                cred.uuid,
                hashlib.sha256(audit_vault.identity(cred)).hexdigest(),
                hashlib.sha256(cred.ciphertext).hexdigest(),
                audit.target,
                audit.port,
                audit.ssh_fingerprint,
                audit.mode,
            ],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    assert audit.winrm_transport == "https"
    assert audit.scope_sha256 == audit_vault.audit_hash(audit, cred) == original_hash
    audit.winrm_transport = "http_ntlm"
    assert audit_vault.audit_hash(audit, cred) != original_hash


@pytest.mark.parametrize("mode", ["inventory", "connection"])
def test_worker_retains_typed_inventory_and_connection_evidence(
    secured, customer, db, monkeypatch, mode
):
    run = queued(secured, customer, mode=mode)
    seen = []

    def collect(payload, cancelled):
        assert not cancelled()
        seen.append(copy.deepcopy(payload))
        return inventory(mode=mode)

    monkeypatch.setattr(host_inventory, "collect", collect)
    job = claim_next_job(db)
    process_job(db, job)
    assert job.status == "finished"
    assert job.progress == 100
    assert seen[0]["secrets"] == {"password": PASSWORD}
    assert seen[0]["ssh_fingerprint"] == FINGERPRINT
    assert PASSWORD not in job.message
    result = secured.get(f"/api/v1/host-audits/{run['id']}").json()
    assert result["inventory"]["os"]["family"] == "Linux"
    assert result["completed_at"]
    assert (
        "inventory"
        not in secured.get(f"/api/v1/host-audits?customer_id={customer['id']}").json()[0]
    )


@pytest.mark.parametrize("change", ["target", "port", "asset", "mode", "credential", "policy"])
def test_worker_rechecks_frozen_identity_before_any_connection(
    secured, customer, db, monkeypatch, change
):
    run = queued(secured, customer)
    audit = db.get(HostAudit, run["id"])
    if change == "target":
        audit.target = "192.0.2.2"
    if change == "port":
        audit.port = 2222
    if change == "asset":
        audit.job.asset_id = None
    if change == "mode":
        audit.mode = "connection"
    if change == "credential":
        audit.credential.username = "changed-account"
    if change == "policy":
        monkeypatch.setenv("CCVM_NETWORK_ALLOWED_CIDRS", "198.51.100.0/24")
    db.commit()
    monkeypatch.setattr(
        host_inventory, "collect", lambda *a, **kw: pytest.fail("must not authenticate")
    )
    process_job(db, claim_next_job(db))
    assert audit.job.status == "failed"


def test_revocation_erases_ciphertext_and_stops_a_running_audit(secured, customer, db, monkeypatch):
    run = queued(secured, customer)

    def collect(payload, cancelled):
        secured.post(f"/api/v1/host-audits/credentials/{run['credential_id']}/revoke")
        assert cancelled()
        raise host_inventory.CollectionCancelled("Credential revoked")

    monkeypatch.setattr(host_inventory, "collect", collect)
    process_job(db, claim_next_job(db))
    assert db.get(AuditCredential, run["credential_id"]).ciphertext is None
    assert db.get(HostAudit, run["id"]).job.status == "cancelled"


def test_cancelled_queue_does_not_authenticate(secured, customer, db):
    run = queued(secured, customer)
    response = secured.post(f"/api/v1/host-audits/{run['id']}/cancel")
    assert response.json()["job"]["status"] == "cancelled"
    assert claim_next_job(db) is None


def test_incomplete_inventory_preserves_evidence_without_a_pass(secured, customer, db, monkeypatch):
    run = queued(secured, customer)
    data = inventory()
    data["packages"] = {"status": "unavailable", "source": "none", "items": []}
    monkeypatch.setattr(host_inventory, "collect", lambda *a, **kw: data)
    process_job(db, claim_next_job(db))
    audit = db.get(HostAudit, run["id"])
    assert audit.job.status == "failed"
    assert audit.inventory["os"]["name"] == "Fixture OS"
    assert "partial evidence retained" in audit.job.message


@pytest.mark.parametrize("exception", [RuntimeError, ValueError])
def test_transport_exceptions_never_reach_messages_or_logs(
    secured, customer, db, monkeypatch, capsys, exception
):
    run = queued(secured, customer)

    def collect(*args, **kwargs):
        raise exception(PASSWORD)

    monkeypatch.setattr(host_inventory, "collect", collect)
    process_job(db, claim_next_job(db))
    assert PASSWORD not in capsys.readouterr().out
    assert PASSWORD not in db.get(HostAudit, run["id"]).job.message


def test_ssh_host_key_checked_before_authentication():
    key = SimpleNamespace(asbytes=lambda: b"synthetic-server-key")
    actual = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip(
        "="
    )
    host_audit_transport.PinnedHostKey(actual).missing_host_key(None, "192.0.2.1", key)
    with pytest.raises(host_audit_transport.TransportFailure, match="host_key_mismatch"):
        host_audit_transport.PinnedHostKey(FINGERPRINT).missing_host_key(None, "192.0.2.1", key)


def test_winrm_disables_redirects_proxies_netrc_and_untrusted_ca_environment():
    calls = []
    response = SimpleNamespace(is_redirect=False, is_permanent_redirect=False, content=b"ok")
    session = SimpleNamespace(send=lambda req, **kw: calls.append(kw) or response)
    endpoint = "https://192.0.2.1:5986/wsman"
    host_audit_transport.restricted_session(session, endpoint, None)
    assert not session.trust_env and session.proxies == {} and session.verify is True
    session.send(SimpleNamespace(url=endpoint), verify=False, proxies={"https": "untrusted"})
    assert calls[0]["verify"] is True and calls[0]["proxies"] == {}
    assert calls[0]["allow_redirects"] is False
    with pytest.raises(host_audit_transport.TransportFailure, match="redirect_rejected"):
        session.send(SimpleNamespace(url="https://198.51.100.1/"))


@pytest.mark.parametrize("change", ["family", "rows", "text", "status"])
def test_remote_inventory_is_bounded_and_typed(change):
    data = inventory()
    if change == "family":
        data["os"]["family"] = "Windows"
    if change == "rows":
        data["packages"]["items"] *= 10001
    if change == "text":
        data["os"]["name"] = "x" * 501
    if change == "status":
        data["packages"]["status"] = "not_requested"
    with pytest.raises(host_inventory.CollectionError):
        host_inventory.normalize_inventory(data, "ssh_password", "inventory")


@pytest.mark.parametrize(
    "status,expected",
    [
        ("queued", "pending"),
        ("running", "pending"),
        ("finished", "unavailable"),
        ("failed", "unavailable"),
        ("cancelled", "not_run"),
        ("skipped", "not_run"),
    ],
)
def test_coverage_never_calls_a_missing_required_result_no_rule(status, expected):
    ssh = {"service": "ssh", "method": "probed", "checks": []}
    assert coverage_for(ssh, status) == expected
    assert coverage_for({"service": "fixture", "method": "probed"}, status) == "no_rule"


def test_coverage_preserves_shared_and_incomplete_evidence():
    service = {
        "service": "netbios-ssn",
        "method": "probed",
        "checks": [{"status": "host-level"}],
    }
    assert coverage_for(service, "finished") == "shared"
    service["checks"].append({"status": "unavailable"})
    assert coverage_for(service, "failed") == "unavailable"


def test_winrm_transport_uses_https_validation_ntlm_and_a_fixed_collector(monkeypatch):
    seen = []
    http = SimpleNamespace(close=lambda: None, send=lambda request, **kw: None)

    def protocol(**options):
        seen.append(options)

        def command(shell, executable, arguments, **kwargs):
            assert shell == "shell" and executable == "powershell"
            assert kwargs["skip_cmd_shell"] is True
            assert "-NoProfile" in arguments and "-NonInteractive" in arguments
            seen.append(base64.b64decode(arguments[-1]).decode("utf-16-le"))
            return "command"

        return SimpleNamespace(
            transport=SimpleNamespace(build_session=lambda: http, endpoint=options["endpoint"]),
            open_shell=lambda **kw: "shell",
            run_command=command,
            get_command_output=lambda *args: (
                __import__("json").dumps(inventory("Windows")).encode(),
                b"",
                0,
            ),
            cleanup_command=lambda *args: seen.append("cleaned-command"),
            close_shell=lambda *args, **kw: seen.append("closed-shell"),
        )

    monkeypatch.setattr(host_audit_transport, "Protocol", protocol)
    result = host_audit_transport.winrm_collect(
        {
            "target": "2001:db8::1",
            "port": 5986,
            "username": "LAB\\inventory",
            "secrets": {"password": PASSWORD},
            "mode": "inventory",
            "ca_bundle": "/fixture/ca.pem",
        }
    )
    assert result["os"]["family"] == "Windows"
    assert seen[0]["endpoint"] == "https://[2001:db8::1]:5986/wsman"
    assert seen[0]["transport"] == "ntlm"
    assert seen[0]["server_cert_validation"] == "validate"
    assert seen[0]["proxy"] is None
    assert seen[0]["send_cbt"] is True
    assert "Win32_Product" not in seen[1]
    assert "Get-HotFix" in seen[1]
    assert PASSWORD not in seen[1]
    assert seen[-2:] == ["cleaned-command", "closed-shell"]


@pytest.mark.parametrize(
    "target,endpoint",
    [
        ("192.0.2.1", "https://192.0.2.1:5986/wsman"),
        ("2001:db8::1", "https://[2001:db8::1]:5986/wsman"),
    ],
)
def test_real_winrm_constructor_preserves_literal_https_endpoint(target, endpoint):
    protocol, url = host_audit_transport.winrm_protocol(
        {
            "target": target,
            "port": 5986,
            "username": "fixture",
            "secrets": {"password": PASSWORD},
        }
    )
    assert url == protocol.transport.endpoint == endpoint
    assert protocol.transport.server_cert_validation == "validate"
    assert protocol.transport.auth_method == "ntlm"


@pytest.mark.parametrize("cancel", [False, True])
def test_transport_hard_deadline_and_cancel_reap_the_process_without_secret_arguments(
    monkeypatch, cancel
):
    events = []

    class Process:
        pid = 12345
        stdin = SimpleNamespace(close=lambda: events.append("stdin-closed"))
        stopped = False

        def communicate(self, input=None, timeout=None):
            assert PASSWORD.encode() in input
            events.append("stdin-only")
            raise subprocess.TimeoutExpired("fixture", timeout)

        def poll(self):
            return 0 if self.stopped else None

        def wait(self, timeout):
            self.stopped = True
            events.append("reaped")

    process = Process()

    def launch(args, **options):
        assert PASSWORD not in str(args)
        assert "CCVM_AUDIT_VAULT_KEY" not in options["env"]
        assert "CCVM_AUDIT_OPERATOR_TOKEN" not in options["env"]
        assert "SSH_AUTH_SOCK" not in options["env"]
        assert options["start_new_session"]
        return process

    ticks = iter([0, 0, 1000])
    monkeypatch.setattr(host_inventory.subprocess, "Popen", launch)
    monkeypatch.setattr(host_inventory.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(host_inventory.os, "killpg", lambda pid, sig: events.append("killed"))
    with pytest.raises(host_inventory.CollectionError, match="cancelled|hard deadline"):
        host_inventory.collect(
            {"mode": "connection", "secrets": {"password": PASSWORD}}, cancelled=lambda: cancel
        )
    assert events[-3:] == ["killed", "reaped", "stdin-closed"]
    if cancel:
        assert "stdin-only" not in events
