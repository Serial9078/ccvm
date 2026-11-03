import copy
import xml.etree.ElementTree as ET
from types import SimpleNamespace

import pytest

from app.database.deps import get_db
from app.main import app
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.host import Host
from app.models.job import Job
from app.models.network_scan import NetworkObservation, NetworkScan
from app.models.port import Port
from app.plugins import network
from app.services import network_rules, nmap
from app.services.network_scope import build_scope, port_ranges
from app.worker.main import claim_next_job, process_job, skip_blocked_jobs

SSH = (
    '<script id="ssh2-enum-algos" output="kex algorithms"><table key="kex_algorithms">'
    "<elem>diffie-hellman-group1-sha1</elem></table></script>"
)


@pytest.fixture(autouse=True)
def scanner_policy(monkeypatch, tmp_path):
    monkeypatch.setenv("CCVM_NETWORK_ALLOWED_CIDRS", "192.0.2.0/24,2001:db8::/120,127.0.0.1/32")
    monkeypatch.setenv("CCVM_NETWORK_LOG_DIR", str(tmp_path / "network-runs"))


@pytest.fixture
def db(client):
    session = next(app.dependency_overrides[get_db]())
    session.autoflush = False
    return session


def payload(customer, **changes):
    return {
        "customer_id": customer["id"],
        "target": "192.0.2.1",
        "profile": "custom",
        "ports": "22",
        **changes,
    }


def queue(client, customer, **changes):
    response = client.post("/api/v1/network-scans", json=payload(customer, **changes))
    assert response.status_code == 201, response.text
    return response.json()


def xml(hosts=("192.0.2.1",), *, ports="22", scripts=(), state="open", version="8.2", errors=()):
    root = ET.Element("nmaprun", scanner="nmap", version="7.95")
    ET.SubElement(root, "scaninfo", protocol="tcp", services=ports)
    selected = sorted(port_ranges(ports)[1])
    for address in hosts:
        host = ET.SubElement(root, "host")
        ET.SubElement(host, "status", state="up", reason="user-set")
        ET.SubElement(host, "address", addr=address, addrtype="ipv6" if ":" in address else "ipv4")
        container = ET.SubElement(host, "ports")
        if state == "closed":
            ET.SubElement(container, "extraports", state="closed", count=str(len(selected)))
            continue
        for number in selected:
            port = ET.SubElement(container, "port", protocol="tcp", portid=str(number))
            ET.SubElement(port, "state", state=state)
            service = ET.SubElement(
                port,
                "service",
                name="ssh",
                method="probed",
                conf="10",
                product="OpenSSH",
                version=version,
            )
            ET.SubElement(service, "cpe").text = "cpe:/a:openbsd:openssh:8.2"
            for script in scripts:
                port.append(ET.fromstring(script))
        for error in errors:
            ET.SubElement(host, "script", id="fixture", output=error)
    stats = ET.SubElement(root, "runstats")
    ET.SubElement(stats, "finished", exit="success")
    return ET.tostring(root, encoding="unicode")


def scanner(monkeypatch, tmp_path, outputs, **execution):
    launches = []

    def run(scan, job, targets, **kwargs):
        directory = tmp_path / f"attempt-{len(launches)}"
        directory.mkdir(parents=True)
        args = nmap.command(
            directory,
            targets,
            **{
                key: kwargs[key] for key in ("profile", "ports", "rate", "timeout_seconds", "audit")
            },
        )
        launches.append((args, targets, kwargs))
        (directory / "results.xml").write_text(outputs.pop(0))
        return nmap.Execution(directory, **{"returncode": 0, **execution})

    monkeypatch.setattr(nmap, "run", run)
    return launches


@pytest.mark.parametrize(
    ("target", "excluded", "expected"),
    [
        ("192.0.2.3/29", ["192.0.2.2/31"], ["192.0.2.1", "192.0.2.4", "192.0.2.5", "192.0.2.6"]),
        ("192.0.2.0/31", [], ["192.0.2.0", "192.0.2.1"]),
        ("2001:db8::/126", ["2001:db8::2"], ["2001:db8::1", "2001:db8::3"]),
    ],
)
def test_scope_is_canonical_and_excluded_addresses_never_reach_target_file(
    target, excluded, expected
):
    scope = build_scope(target, excluded, "custom", "22,21-23,443", 100, 600)
    assert scope.targets == expected and scope.ports == "21-23,443"


@pytest.mark.parametrize(
    "changes",
    [
        {"target": "example.test"},
        {"target": "192.0.2.1;touch /tmp/x"},
        {"target": "2001:db8::/32"},
        {"target": "10.0.0.0/8"},
        {"target": "224.0.0.1"},
        {"ports": "22 --script=unsafe"},
        {"ports": "0,65536"},
        {"exclusions": ["192.0.2.1"]},
        {"exclusions": ["::1"]},
        {"target": "192.0.2.0/24", "profile": "full", "ports": None, "timeout_seconds": 60},
    ],
)
def test_invalid_or_unbounded_scope_never_queues_jobs(client, customer, db, changes):
    response = client.post("/api/v1/network-scans", json=payload(customer, **changes))
    assert response.status_code == 422, response.text
    assert db.query(NetworkScan).count() == db.query(Job).count() == 0


def test_preview_is_read_only_and_scope_policy_is_enforced_twice(client, customer, db, monkeypatch):
    response = client.post(
        "/api/v1/network-scans/preview",
        json=payload(customer, target="192.0.2.0/29", exclusions=["192.0.2.2/31"]),
    )
    assert response.status_code == 200
    assert response.json()["address_count"] == 4
    assert db.query(Asset).count() == db.query(Job).count() == 0
    run = queue(client, customer)
    monkeypatch.setenv("CCVM_NETWORK_ALLOWED_CIDRS", "192.0.2.128/25")
    process_job(db, claim_next_job(db))
    job = db.get(Job, run["jobs"][0]["id"])
    assert job.status == "failed" and "outside" in job.message
    assert db.query(Host).count() == 0


def test_default_disabled_requires_scanner_networks(client, customer, db, monkeypatch):
    monkeypatch.delenv("CCVM_NETWORK_ALLOWED_CIDRS")
    assert client.get("/api/v1/network-scans/capabilities").json()["enabled"] is False
    response = client.post("/api/v1/network-scans", json=payload(customer))
    assert response.status_code == 422 and "disabled" in response.text
    assert db.query(Job).count() == 0


def test_queue_freezes_identity_and_blocks_duplicate_or_unscoped_jobs(client, customer, db):
    run = queue(client, customer)
    assert [job["plugin"] for job in run["jobs"]] == ["networkdiscovery", "networkaudit"]
    assert run["jobs"][1]["parent_job_id"] == run["jobs"][0]["id"]
    assert client.post("/api/v1/network-scans", json=payload(customer)).status_code == 409
    assert (
        client.post(
            "/api/v1/jobs", json={"plugin": "networkaudit", "asset_id": run["asset_id"]}
        ).status_code
        == 400
    )
    pipeline = client.get("/api/v1/pipelines/" + run["pipeline_id"]).json()
    assert pipeline["asset_target"] == "192.0.2.1/32" and pipeline["domain_id"] is None
    db.get(Asset, run["asset_id"]).target = "198.51.100.1"
    db.commit()
    assert db.get(NetworkScan, run["id"]).targets == ["192.0.2.1"]
    assert client.post("/api/v1/network-scans", json=payload(customer)).status_code == 409


def test_complete_network_pipeline_finds_real_protocol_evidence_and_updates_idempotently(
    client, customer, db, monkeypatch, tmp_path
):
    other = client.post("/api/v1/customers", json={"name": "Other customer"}).json()
    other_asset = Asset(customer_id=other["id"], target="192.0.2.1", type="ip")
    db.add(other_asset)
    db.flush()
    foreign = Finding(
        asset_id=other_asset.id,
        scanner="network-audit",
        template_id="nmap:ssh-legacy-kex",
        matched_at="tcp://192.0.2.1:22",
        name="Other customer's finding",
        status="fixed",
    )
    db.add(foreign)
    db.commit()
    run = queue(client, customer)
    launches = scanner(monkeypatch, tmp_path, [xml(version="V" * 2000), xml(scripts=[SSH])])
    process_job(db, claim_next_job(db))
    process_job(db, claim_next_job(db))
    result = client.get(f"/api/v1/network-scans/{run['id']}").json()
    assert result["status"] == "finished" and result["findings_created"] == 1
    assert result["open_services"] == result["hosts_checked"] == 1
    finding = db.query(Finding).filter(Finding.asset_id != other_asset.id).one()
    assert finding.scanner == "network-audit" and finding.cve is None
    assert db.get(Asset, finding.asset_id).customer_id == customer["id"]
    assert finding.asset_id != other_asset.id and finding.matched_at == "tcp://192.0.2.1:22"
    assert "diffie-hellman-group1-sha1" in finding.raw_json
    assert result["observations"][0]["services"][0]["checks"][0]["status"] == "completed"
    assert all(
        targets == ["192.0.2.1"] and "-n" in args and "-sT" in args
        for args, targets, options in launches
    )
    assert ",".join(nmap.AUDIT_SCRIPTS) in launches[1][0]
    job = db.get(Job, run["jobs"][1]["id"])
    job.status = "running"
    scanner(monkeypatch, tmp_path / "repeat", [xml(scripts=[SSH])])
    (tmp_path / "repeat").mkdir()
    network.run_networkaudit(db, job)
    assert db.query(Finding).count() == 2 and db.get(NetworkScan, run["id"]).findings_updated == 1
    db.refresh(foreign)
    assert foreign.status == "fixed" and foreign.name == "Other customer's finding"


@pytest.mark.parametrize("mode", ["nonzero", "coverage", "outside", "incomplete-xml", "timeout"])
def test_partial_or_invalid_scan_is_failed_and_downstream_is_skipped(
    client, customer, db, monkeypatch, tmp_path, mode
):
    run = queue(client, customer)
    output = xml()
    if mode == "coverage":
        output = xml(hosts=())
    elif mode == "outside":
        output = xml(hosts=("198.51.100.1",))
    elif mode == "incomplete-xml":
        output = "<nmaprun>"
    scanner(
        monkeypatch,
        tmp_path,
        [output],
        returncode=1 if mode == "nonzero" else 0,
        timedout=mode == "timeout",
    )
    process_job(db, claim_next_job(db))
    skip_blocked_jobs(db)
    result = client.get(f"/api/v1/network-scans/{run['id']}").json()
    assert result["status"] == "failed" and result["jobs"][1]["status"] == "skipped"
    if mode in {"outside", "coverage", "incomplete-xml"}:
        assert db.query(Host).count() == 0


def test_silence_in_a_probed_protocol_is_incomplete_not_a_clean_audit(
    client, customer, db, monkeypatch, tmp_path
):
    run = queue(client, customer)
    scanner(monkeypatch, tmp_path, [xml(), xml()])
    process_job(db, claim_next_job(db))
    process_job(db, claim_next_job(db))
    result = client.get(f"/api/v1/network-scans/{run['id']}").json()
    assert result["status"] == "failed" and "checks unavailable" in result["jobs"][1]["message"]
    assert result["findings_created"] == 0


def test_cancel_queued_scan_starts_nothing(client, customer, db):
    run = queue(client, customer)
    assert client.post(f"/api/v1/network-scans/{run['id']}/cancel").status_code == 200
    assert claim_next_job(db) is None
    assert all(job.status == "cancelled" for job in db.query(Job).all())
    assert client.get("/api/v1/pipelines/" + run["pipeline_id"]).json()["status"] == "cancelled"


def test_empty_enumeration_is_incomplete_and_cpe_never_becomes_a_guessed_cve(
    client, customer, db, monkeypatch, tmp_path
):
    run = queue(client, customer)
    empty = (
        '<script id="ssh2-enum-algos" output="kex algorithms">'
        '<table key="kex_algorithms"/></script>'
    )
    scanner(monkeypatch, tmp_path, [xml(), xml(scripts=[empty])])
    process_job(db, claim_next_job(db))
    process_job(db, claim_next_job(db))
    assert db.query(Finding).count() == 0
    assert db.get(Job, run["jobs"][1]["id"]).status == "failed"


def test_partial_audit_keeps_positive_findings_but_fails_the_job(
    client, customer, db, monkeypatch, tmp_path
):
    run = queue(client, customer)
    scanner(monkeypatch, tmp_path / "discovery", [xml()])
    process_job(db, claim_next_job(db))
    scanner(monkeypatch, tmp_path / "audit", [xml(scripts=[SSH])], returncode=1)
    process_job(db, claim_next_job(db))
    assert db.get(Job, run["jobs"][1]["id"]).status == "failed"
    assert db.query(Finding).count() == 1


def test_rescan_updates_closed_port_state_without_fabricating_host_death(
    client, customer, db, monkeypatch, tmp_path
):
    first = queue(client, customer)
    scanner(monkeypatch, tmp_path / "first", [xml(), xml(scripts=[SSH])])
    process_job(db, claim_next_job(db))
    process_job(db, claim_next_job(db))
    second = queue(client, customer)
    scanner(monkeypatch, tmp_path / "second", [xml(state="closed")])
    process_job(db, claim_next_job(db))
    process_job(db, claim_next_job(db))
    assert db.query(Port).one().state == "closed"
    assert db.query(Host).one().alive is True
    assert db.get(Job, second["jobs"][1]["id"]).status == "finished"
    assert db.query(Finding).one().status == "open"  # No unsupported automatic remediation claim.
    assert first["asset_id"] == second["asset_id"]


def test_modified_frozen_targets_are_refused_before_any_probe(client, customer, db):
    run = queue(client, customer)
    scan = db.get(NetworkScan, run["id"])
    scan.targets = ["192.0.2.99"]
    db.commit()
    process_job(db, claim_next_job(db))
    assert db.get(Job, run["jobs"][0]["id"]).status == "failed"
    assert db.query(Host).count() == 0


def test_reassigned_customer_cannot_redirect_a_queued_scan(client, customer, db):
    run = queue(client, customer)
    other = client.post("/api/v1/customers", json={"name": "Changed owner"}).json()
    db.get(NetworkScan, run["id"]).customer_id = other["id"]
    db.get(Asset, run["asset_id"]).customer_id = other["id"]
    db.commit()
    process_job(db, claim_next_job(db))
    assert db.get(Job, run["jobs"][0]["id"]).status == "failed"
    assert db.query(Host).count() == 0


def test_changed_snapshot_and_escaping_audit_ports_are_refused(
    client, customer, db, monkeypatch, tmp_path
):
    run = queue(client, customer)
    scanner(monkeypatch, tmp_path, [xml()])
    process_job(db, claim_next_job(db))
    observation = db.query(NetworkObservation).one()
    service = copy.deepcopy(observation.services)
    service[0]["port"] = 4444
    observation.services = service
    db.commit()
    process_job(db, claim_next_job(db))
    assert db.get(Job, run["jobs"][1]["id"]).status == "failed"
    assert "escaped" in db.get(Job, run["jobs"][1]["id"]).message


def test_xml_entities_and_duplicate_hosts_are_refused(tmp_path):
    path = tmp_path / "bad.xml"
    path.write_text('<!DOCTYPE nmaprun [<!ENTITY x "evil">]><nmaprun/>')
    with pytest.raises(ValueError, match="entity"):
        nmap.parse(path, ["192.0.2.1"])
    path.write_text(xml(hosts=("192.0.2.1", "192.0.2.1")))
    with pytest.raises(ValueError, match="duplicate"):
        nmap.parse(path, ["192.0.2.1"])


def test_truncated_xml_retains_only_completed_hosts_and_is_incomplete(
    client, customer, db, monkeypatch, tmp_path
):
    run = queue(client, customer)
    output = xml().split("<runstats>")[0]
    scanner(monkeypatch, tmp_path, [output], returncode=1)
    process_job(db, claim_next_job(db))
    assert db.get(Job, run["jobs"][0]["id"]).status == "failed"
    assert db.query(Port).one().state == "open"
    assert db.query(NetworkObservation).count() == 1


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (SSH, ["ssh-legacy-kex"]),
        (
            '<script id="smb-protocols" output="SMB"><table key="dialects">'
            "<elem>NT LM 0.12 (SMBv1) [dangerous, but default]</elem></table></script>",
            ["smb1-enabled"],
        ),
        (
            '<script id="smb-protocols" output="SMBv1 not supported"><table key="error">'
            "<elem>SMBv1 not supported</elem></table></script>",
            [],
        ),
        (
            '<script id="ssl-enum-ciphers" output="TLS"><table key="TLSv1.0">'
            '<table key="ciphers"><table><elem key="name">TLS_RSA_WITH_AES_128_CBC_SHA</elem>'
            "</table></table></table></script>",
            ["tls-legacy-protocol"],
        ),
        (
            '<script id="smb2-security-mode" output="Message signing enabled but not required"/>',
            ["smb-signing-optional"],
        ),
        ('<script id="rdp-enum-encryption" output="Native RDP: SUCCESS"/>', ["rdp-without-nla"]),
        (
            '<script id="rdp-enum-encryption" '
            'output="CredSSP (NLA): SUCCESS; Native RDP: FAILED"/>',
            [],
        ),
        ('<script id="ssh2-enum-algos" output="ERROR: no negotiation"/>', []),
    ],
)
def test_protocol_rules_require_positive_evidence(source, expected):
    node = ET.fromstring(source)
    assert [
        item["key"] for item in network_rules.findings({}, [nmap.script_data(node)])
    ] == expected


@pytest.mark.parametrize("stop", ["cancel", "timeout", "callback-error"])
def test_running_scanner_is_reaped_on_cancellation_timeout_or_error(monkeypatch, tmp_path, stop):
    calls = []
    process = SimpleNamespace(returncode=None)
    process.poll = lambda: process.returncode
    process.terminate = lambda: calls.append("terminate")
    process.kill = lambda: calls.append("kill")

    def wait(**kwargs):
        process.returncode = -15
        return -15

    process.wait = wait
    monkeypatch.setattr(nmap.subprocess, "Popen", lambda *args, **kwargs: process)
    ticks = iter([0, 100, 101])
    monkeypatch.setattr(nmap.time, "monotonic", lambda: next(ticks, 101))

    def update(*args):
        if stop == "callback-error":
            raise RuntimeError("fixture database error")
        return stop == "cancel"

    options = dict(
        profile="custom", ports="22", rate=100, timeout_seconds=60, audit=False, update=update
    )
    if stop == "callback-error":
        with pytest.raises(RuntimeError):
            nmap.run(1, 1, ["192.0.2.1"], **options)
        assert calls == ["kill"]
    else:
        result = nmap.run(1, 1, ["192.0.2.1"], **options)
        assert result.cancelled is (stop == "cancel")
        assert result.timedout is (stop == "timeout")
        assert calls == ["terminate"]
    assert process.returncode is not None
