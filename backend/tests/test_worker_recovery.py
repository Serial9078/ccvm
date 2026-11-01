"""Offline checks for the explicit worker maintenance command."""

import importlib.util
import io
import json
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.orm import sessionmaker

from app.database.deps import get_db
from app.main import app
from app.models.asset import Asset
from app.models.job import Job
from app.models.url import Url

SPEC = importlib.util.spec_from_file_location(
    "worker_recovery",
    Path(__file__).resolve().parents[2] / "scripts/recover-worker.py",
)
RECOVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECOVERY)
IDENTITIES = [
    (17, "11111111-1111-4111-8111-111111111111"),
    (29, "22222222-2222-4222-8222-222222222222"),
]


@pytest.fixture
def db(client):
    yield from app.dependency_overrides[get_db]()


@pytest.fixture
def interrupted(client, customer, domain, db):
    asset = Asset(customer_id=customer["id"], target="https://example.test")
    db.add(asset)
    db.flush()
    db.add_all(
        [
            Job(
                id=17,
                uuid=IDENTITIES[0][1],
                asset_id=asset.id,
                plugin="nuclei",
                status="running",
                progress=10,
                message="Old scan",
                worker="ccvm-worker-01",
            ),
            Job(
                id=29,
                uuid=IDENTITIES[1][1],
                domain_id=domain["id"],
                plugin="katana",
                status="running",
                progress=52,
                message="Old crawl",
                worker="ccvm-worker-01",
            ),
            Url(
                customer_id=customer["id"],
                domain_id=domain["id"],
                url="https://example.test/",
            ),
        ]
    )
    db.commit()
    return sorted(client.get("/api/v1/jobs").json(), key=lambda row: row["id"])


def execute_repair(monkeypatch, db, snapshots, stopped=True):
    db.commit()
    monkeypatch.setattr("app.database.session.SessionLocal", sessionmaker(bind=db.get_bind()))
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({"worker_stopped": stopped, "jobs": snapshots})),
    )
    exec(compile(RECOVERY.RECOVER_IN_BACKEND, "<reviewed-recovery-code>", "exec"), {})
    db.expire_all()


def test_repair_only_closes_selected_jobs_and_preserves_scan_data(interrupted, db, monkeypatch):
    execute_repair(monkeypatch, db, interrupted)
    for before in interrupted:
        job = db.get(Job, before["id"])
        assert job.status == "failed" and job.progress == 100
        assert "execution was not completed" in job.message
        for field in set(before) - {"status", "progress", "message"}:
            assert getattr(job, field) == before[field]
    assert db.query(Url).count() == db.query(Asset).count() == 1
    assert db.query(Job).count() == 2


@pytest.mark.parametrize(
    ("field", "wrong"),
    [
        ("uuid", "changed"),
        ("progress", 53),
        ("message", "New crawl"),
        ("worker", "other-worker"),
        ("pipeline_id", "new-pipeline"),
        ("status", "finished"),
    ],
)
def test_repair_rechecks_all_snapshots_before_any_write(interrupted, db, monkeypatch, field, wrong):
    interrupted[1][field] = wrong
    with pytest.raises(RuntimeError, match="Job changed since backup: 29"):
        execute_repair(monkeypatch, db, interrupted)
    db.expire_all()
    assert [job.status for job in db.query(Job).order_by(Job.id)] == [
        "running",
        "running",
    ]


@pytest.mark.parametrize("status", ["queued", "running"])
def test_repair_refuses_new_active_work(interrupted, db, monkeypatch, status):
    db.add(Job(plugin="dummy", status=status))
    db.commit()
    with pytest.raises(RuntimeError, match="Another active job appeared"):
        execute_repair(monkeypatch, db, interrupted)
    db.expire_all()
    assert db.get(Job, 17).status == db.get(Job, 29).status == "running"


def test_repair_preserves_already_finished_job(interrupted, client, db, monkeypatch):
    job = db.get(Job, 17)
    job.status, job.progress, job.message = "finished", 100, "Completed earlier"
    db.commit()
    snapshots = client.get("/api/v1/jobs").json()
    execute_repair(monkeypatch, db, snapshots)
    assert db.get(Job, 17).status == "finished"
    assert db.get(Job, 17).message == "Completed earlier"
    assert db.get(Job, 29).status == "failed"


@pytest.mark.parametrize(
    "defect", ["worker-running", "missing-field", "duplicate-id", "missing-job"]
)
def test_repair_refuses_invalid_context(interrupted, db, monkeypatch, defect):
    stopped = defect != "worker-running"
    if defect == "missing-field":
        interrupted[0].pop("uuid")
    elif defect == "duplicate-id":
        interrupted.append(interrupted[0].copy())
    elif defect == "missing-job":
        db.delete(db.get(Job, 29))
        db.commit()
    with pytest.raises(RuntimeError):
        execute_repair(monkeypatch, db, interrupted, stopped)
    db.expire_all()
    assert db.get(Job, 17).status == "running"


@pytest.mark.parametrize(
    "defect", ["wrong-uuid", "other-queued", "selected-queued", "duplicate-id"]
)
def test_host_selection_refuses_ambiguous_or_live_work(interrupted, defect):
    identities = IDENTITIES.copy()
    if defect == "wrong-uuid":
        identities[0] = (17, "wrong")
    elif defect == "other-queued":
        interrupted.append({"id": 38, "status": "queued"})
    elif defect == "selected-queued":
        interrupted[0]["status"] = "queued"
    else:
        identities.append(identities[0])
    with pytest.raises(RuntimeError):
        RECOVERY.select_jobs(interrupted, identities)


def test_backup_is_private_and_cannot_overwrite(tmp_path):
    backup = tmp_path / "before.json"
    RECOVERY.write_json(backup, {"progress": 52})
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        RECOVERY.write_json(backup, {"progress": 100})
    assert json.loads(backup.read_text()) == {"progress": 52}


@pytest.mark.parametrize("failure", ["stop", "merge", "exec"])
def test_failure_resumes_worker_and_backup_precedes_mutations(
    interrupted, tmp_path, monkeypatch, failure
):
    calls = []

    def fake_command(root, *args, **kwargs):
        assert json.loads((tmp_path / "jobs-before.json").read_text())["jobs"] == interrupted
        calls.append(args)
        if args[:2] == ("docker", failure) or args[:2] == ("git", failure):
            raise RuntimeError("Controlled failure")
        if args[:2] == ("docker", "inspect"):
            return "false"
        return ""

    monkeypatch.setattr(RECOVERY, "command", fake_command)
    with pytest.raises(RuntimeError, match="Controlled failure"):
        RECOVERY.recover(tmp_path, "a" * 40, None, interrupted, tmp_path)
    assert calls[-1] == ("docker", "start", "ccvm-worker")
    assert not (tmp_path / "recovery-result.json").exists()


def test_successful_recovery_verifies_api_after_restart(interrupted, tmp_path, monkeypatch):
    calls = []

    def fake_command(root, *args, **kwargs):
        calls.append(args)
        if args[:2] == ("docker", "inspect"):
            return "false"
        if args[:2] == ("docker", "exec"):
            assert json.loads(kwargs["input_text"]) == {
                "worker_stopped": True,
                "jobs": interrupted,
            }
            return '{"closed_as_failed": [17, 29]}'
        return ""

    after = [{**job, "status": "failed"} for job in interrupted]
    api = SimpleNamespace(request=lambda path: after)
    monkeypatch.setattr(RECOVERY, "command", fake_command)
    RECOVERY.recover(tmp_path, "a" * 40, api, interrupted, tmp_path)
    assert calls[-1] == ("docker", "start", "ccvm-worker")
    assert json.loads((tmp_path / "recovery-result.json").read_text())["closed_as_failed"] == [
        17,
        29,
    ]


@pytest.mark.parametrize("container", ["ccvm-worker", "ccvm-nuclei", "ccvm-backend"])
def test_preflight_refuses_scanner_or_additional_process(tmp_path, monkeypatch, container):
    def fake_command(root, *args, **kwargs):
        if args[:2] == ("docker", "ps"):
            return "ccvm-worker\nccvm-backend\nccvm-nuclei"
        if args[:2] == ("docker", "top"):
            expected = {
                "ccvm-worker": "python",
                "ccvm-nuclei": "tail",
                "ccvm-backend": "sh\nuvicorn",
            }
            return "COMMAND\n" + expected[args[2]] + ("\nkatana" if args[2] == container else "")
        raise AssertionError(args)

    monkeypatch.setattr(RECOVERY, "command", fake_command)
    with pytest.raises(RuntimeError, match="Unexpected processes"):
        RECOVERY.check_processes(tmp_path)


def test_mutating_http_request_is_never_retried(monkeypatch):
    attempts = []

    def lost_response(request, timeout):
        attempts.append(request)
        raise OSError("Response lost after enqueue")

    api = RECOVERY.API()
    monkeypatch.setattr(api.opener, "open", lost_response)
    with pytest.raises(OSError, match="Response lost"):
        api.request("/api/v1/discover", {"domain_id": 1})
    assert len(attempts) == 1 and attempts[0].get_method() == "POST"


def test_existing_pilot_is_resumed_without_restart_or_duplicate_post(tmp_path, monkeypatch):
    marker = tmp_path / "ccvm-worker-recovery-pipeline.json"
    RECOVERY.write_json(
        marker,
        {
            "target": "a" * 40,
            "domain": "example.test",
            "pipeline": {"pipeline_id": "pilot-id"},
        },
    )
    args = SimpleNamespace(target="a" * 40, domain="example.test", apply=True, start_pipeline=True)
    commands, monitored = [], []
    monkeypatch.setattr(RECOVERY, "command", lambda root, *args, **kwargs: commands.append(args))
    monkeypatch.setattr(RECOVERY, "monitor", lambda api, *args: monitored.append(args))
    RECOVERY.execute(args, tmp_path, tmp_path, None)
    assert commands == [("git", "merge-base", "--is-ancestor", "a" * 40, "HEAD")]
    assert monitored == [("pilot-id", "example.test")]


def test_dry_run_preserves_files_and_only_reads_api(tmp_path, interrupted, monkeypatch):
    root, git_dir = tmp_path, tmp_path / "git"
    git_dir.mkdir()
    posts = []
    replies = {
        "/health": {"status": "ok", "version": "4.4.0"},
        "/api/v1/jobs": interrupted,
        "/api/v1/domains": [{"id": 1, "name": "example.test", "customer_id": 1}],
        "/api/v1/subdomains": [],
        "/api/v1/hosts": [],
        "/api/v1/urls?domain_id=1": [],
        "/api/v1/assets": [{"customer_id": 1}],
    }

    def request(path, payload=None):
        if payload is not None:
            posts.append(payload)
            raise AssertionError("Dry run attempted a write")
        return replies[path]

    def fake_command(root, *args, **kwargs):
        if args == ("git", "branch", "--show-current"):
            return RECOVERY.BRANCH
        if args[:2] == ("docker", "exec"):
            return "-disable-redirects"
        if args[:2] == ("git", "ls-files"):
            return "backend/app/plugins/nucleiurl.py.bak-final"
        if args[0] == "git":
            return ""
        raise AssertionError(args)

    args = SimpleNamespace(target="a" * 40, domain="example.test", apply=False, job=IDENTITIES)
    monkeypatch.setattr(RECOVERY, "command", fake_command)
    monkeypatch.setattr(RECOVERY, "check_processes", lambda root: None)
    RECOVERY.execute(args, root, git_dir, SimpleNamespace(request=request))
    assert not posts and list(git_dir.iterdir()) == []


def test_full_maintenance_and_repeat_preserve_configuration(
    tmp_path, interrupted, client, db, monkeypatch
):
    git_dir = tmp_path / "git"
    git_dir.mkdir()
    private = {
        "docker-compose.yml": b"private compose\n",
        "frontend/default.conf": b"private nginx\n",
        ".env": b"private environment\n",
    }
    for name, contents in private.items():
        path = tmp_path / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(contents)
    calls, posts = [], []
    worker_running = True

    def request(path, payload=None):
        response = client.request("GET" if payload is None else "POST", path, json=payload)
        assert response.status_code == 200, response.text
        data = response.json()
        if payload is not None:
            posts.append(path)
            # Simulate completed work; scanners and worker processes remain blocked.
            ids = [data["id"]] if path == "/api/v1/jobs" else [job["id"] for job in data["jobs"]]
            for identifier in ids:
                job = db.get(Job, identifier)
                job.status, job.progress = "finished", 100
            db.commit()
        return data

    def fake_command(root, *args, **kwargs):
        nonlocal worker_running
        calls.append(args)
        if args == ("git", "branch", "--show-current"):
            return RECOVERY.BRANCH
        if args == ("git", "rev-parse", "HEAD"):
            return "b" * 40
        if args[:2] == ("git", "diff"):
            return "" if "--" in args else "scripts/recover-worker.py"
        if args[:2] == ("git", "ls-files"):
            return "backend/app/plugins/nucleiurl.py.bak-final"
        if args[0] == "git":
            return ""
        if args[:2] == ("docker", "ps"):
            return "ccvm-worker\nccvm-backend\nccvm-nuclei"
        if args[:2] == ("docker", "top"):
            return (
                "COMMAND\n"
                + {"ccvm-worker": "python", "ccvm-backend": "sh\nuvicorn", "ccvm-nuclei": "tail"}[
                    args[2]
                ]
            )
        if args[:2] == ("docker", "inspect"):
            if "{{json .Mounts}}" in args:
                return json.dumps([{"Destination": "/app", "Source": str(root / "backend")}])
            return json.dumps(worker_running)
        if args[:2] == ("docker", "stop"):
            assert list(git_dir.glob("ccvm-worker-recovery-*/jobs-before.json"))
            worker_running = False
            return "ccvm-worker"
        if args[:2] == ("docker", "start"):
            worker_running = True
            return "ccvm-worker"
        if args[:2] == ("docker", "exec"):
            if "nuclei" in args:
                return "-disable-redirects"
            assert not worker_running
            payload = json.loads(kwargs["input_text"])
            execute_repair(monkeypatch, db, payload["jobs"], payload["worker_stopped"])
            return '{"closed_as_failed": [17, 29]}'
        raise AssertionError(args)

    args = SimpleNamespace(
        target="a" * 40, domain="example.test", apply=True, start_pipeline=True, job=IDENTITIES
    )
    api = SimpleNamespace(request=request)
    monkeypatch.setattr(RECOVERY, "command", fake_command)
    RECOVERY.execute(args, tmp_path, git_dir, api)
    RECOVERY.execute(args, tmp_path, git_dir, api)
    assert worker_running
    assert posts == ["/api/v1/jobs", "/api/v1/discover"]
    assert sum(call[:2] == ("docker", "stop") for call in calls) == 1
    assert db.get(Job, 17).status == db.get(Job, 29).status == "failed"
    assert db.query(Job).count() == 13
    for name, contents in private.items():
        assert (tmp_path / name).read_bytes() == contents


@pytest.mark.parametrize(
    "path,record",
    [
        ("subdomains", {"domain_id": 1, "name": "notexample.test"}),
        ("hosts", {"domain_id": 1, "hostname": "example.test.other.test"}),
        ("urls?domain_id=1", {"url": "https://other.test/"}),
    ],
)
def test_pilot_preflight_rejects_foreign_stored_targets(path, record):
    def request(route):
        if route == "/api/v1/domains":
            return [{"id": 1, "name": "example.test", "customer_id": 1}]
        if route == "/api/v1/" + path:
            return [record]
        return []

    with pytest.raises(RuntimeError, match="outside"):
        RECOVERY.check_domain(SimpleNamespace(request=request), "example.test")
