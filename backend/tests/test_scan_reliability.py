"""Regressions for incomplete scans and actual worker sessions; no external IO."""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.database.deps import get_db
from app.main import app
from app.models.asset import Asset
from app.models.customer import Customer
from app.models.finding import Finding
from app.models.job import Job
from app.models.url import Url
from app.models.url_detail import UrlDetail
from app.plugins import nucleiurl, urlprobe
from app.worker import main as worker


@pytest.fixture
def db(client):
    session = next(app.dependency_overrides[get_db]())
    # The worker disables autoflush; the original fixture hid duplicate imports.
    session.autoflush = False
    return session


@pytest.fixture
def scan(db, domain, customer):
    asset = Asset(customer_id=customer["id"], target="https://example.test/")
    url = Url(customer_id=customer["id"], domain_id=domain["id"], url="https://example.test/")
    job = Job(domain_id=domain["id"], plugin="nucleiurl", status="running")
    db.add_all([asset, url, job])
    db.flush()
    db.add(UrlDetail(url_id=url.id, status_code=200, content_type="text/html"))
    db.commit()
    return SimpleNamespace(asset=asset, url=url, job=job)


def finding_result(**extra):
    return {
        "template-id": "ci-template",
        "matched-at": "https://example.test/",
        "info": {"name": "Synthetic finding", "severity": "low"},
        **extra,
    }


def mock_scanner(monkeypatch, *, lines=(), exit_code=0, timeout=False, stats=()):
    monkeypatch.setattr(nucleiurl, "prepare_templates", lambda: Path("/ci/nuclei-templates"))
    launches, sleeps = [], []
    process = SimpleNamespace(returncode=exit_code)
    polls = iter([None, exit_code] if stats or timeout else [exit_code])
    process.poll = lambda: next(polls, process.returncode)
    process.terminate = lambda: launches.append("terminate")
    process.kill = lambda: launches.append("kill")
    process.wait = lambda **kwargs: process.returncode

    def launch(command, **kwargs):
        launches.append(command)
        Path(command[command.index("-o") + 1]).write_text("\n".join(lines))
        kwargs["stderr"].write("\n".join(stats) + "\n")
        kwargs["stderr"].flush()
        return process

    clock = iter([0, nucleiurl.NUCLEI_TIMEOUT_SECONDS if timeout else 600])
    monkeypatch.setattr(nucleiurl.subprocess, "Popen", launch)
    monkeypatch.setattr(nucleiurl.time, "monotonic", lambda: next(clock, 600))
    monkeypatch.setattr(nucleiurl.time, "sleep", lambda seconds: sleeps.append(seconds))
    return launches, sleeps


@pytest.mark.parametrize("exit_code", [1, 2, 137])
def test_nonzero_exit_is_failed_even_with_partial_findings(db, scan, monkeypatch, exit_code):
    mock_scanner(monkeypatch, lines=[json.dumps(finding_result())], exit_code=exit_code)
    nucleiurl.run_nucleiurl(db, scan.job)
    assert scan.job.status == "failed", scan.job.message
    assert str(exit_code) in scan.job.message
    assert db.query(Finding).count() == 1


def test_hard_timeout_is_incomplete_and_keeps_partial_findings(db, scan, monkeypatch):
    launches, sleeps = mock_scanner(monkeypatch, lines=[json.dumps(finding_result())], timeout=True)
    nucleiurl.run_nucleiurl(db, scan.job)
    assert scan.job.status == "failed", scan.job.message
    assert "timeout" in scan.job.message.lower()
    assert "terminate" in launches and not sleeps
    assert db.query(Finding).count() == 1


def test_success_without_findings_is_success(db, scan, monkeypatch):
    mock_scanner(monkeypatch)
    nucleiurl.run_nucleiurl(db, scan.job)
    assert scan.job.status == "finished" and scan.job.progress == 100
    assert db.query(Finding).count() == 0


def test_template_preparation_failure_is_failed_before_scanner_launch(db, scan, monkeypatch):
    def unavailable():
        raise RuntimeError("template download unavailable")

    monkeypatch.setattr(nucleiurl, "prepare_templates", unavailable)
    nucleiurl.run_nucleiurl(db, scan.job)
    assert scan.job.status == "failed" and scan.job.progress == 100
    assert "template download unavailable" in scan.job.message


def test_duplicate_lines_are_idempotent_with_worker_autoflush_disabled(db, scan, monkeypatch):
    mock_scanner(monkeypatch, lines=[json.dumps(finding_result())] * 3)
    nucleiurl.run_nucleiurl(db, scan.job)
    assert scan.job.status == "finished", scan.job.message
    assert db.query(Finding).count() == 1
    assert "Created: 1" in scan.job.message and "Updated: 2" in scan.job.message


def test_import_does_not_move_another_customers_finding(db, scan):
    other_customer = Customer(name="Other synthetic tenant")
    db.add(other_customer)
    db.flush()
    other_asset = Asset(customer_id=other_customer.id, target="https://example.test/")
    db.add(other_asset)
    db.flush()
    other = Finding(
        asset_id=other_asset.id,
        scanner="nuclei-url",
        template_id="ci-template",
        matched_at="https://example.test/",
        name="Other tenant evidence",
        status="fixed",
    )
    db.add(other)
    db.commit()
    assert nucleiurl.import_nuclei_result(db, scan.job, scan.asset, finding_result()) == (
        True,
        False,
    )
    db.commit()
    assert other.asset_id == other_asset.id and other.status == "fixed"
    assert db.query(Finding).count() == 2


def test_rescan_updates_and_reopens_same_asset_finding(db, scan):
    nucleiurl.import_nuclei_result(db, scan.job, scan.asset, finding_result())
    db.commit()
    existing = db.query(Finding).one()
    existing.status = "fixed"
    db.commit()
    assert nucleiurl.import_nuclei_result(db, scan.job, scan.asset, finding_result()) == (
        False,
        True,
    )
    db.commit()
    assert db.query(Finding).count() == 1 and existing.status == "open"


@pytest.mark.parametrize(
    "bad_line",
    [
        "{invalid",
        "[]",
        "null",
        '{"info": "invalid"}',
        '{"info": {"classification": []}, "matched-at": "https://example.test/"}',
    ],
)
def test_malformed_results_do_not_lose_valid_evidence(db, scan, monkeypatch, bad_line):
    mock_scanner(monkeypatch, lines=[bad_line, json.dumps(finding_result())])
    nucleiurl.run_nucleiurl(db, scan.job)
    assert scan.job.status == "failed", scan.job.message
    assert "Malformed results: 1" in scan.job.message
    assert db.query(Finding).count() == 1


def test_live_progress_uses_scanner_stats_instead_of_elapsed_timeout(db, scan, monkeypatch):
    launches, _ = mock_scanner(
        monkeypatch,
        stats=[
            "[INF] noise",
            json.dumps({"percent": "20", "requests": "40", "total": "200", "matched": "0"}),
        ],
    )
    observed = []
    monkeypatch.setattr(
        nucleiurl.time,
        "sleep",
        lambda seconds: observed.append((scan.job.progress, scan.job.message)),
    )
    nucleiurl.run_nucleiurl(db, scan.job)
    assert "-stats-json" in launches[0]
    assert launches[0][launches[0].index("-t") + 1] == "/ci/nuclei-templates"
    assert launches[0][launches[0].index("-update-template-dir") + 1] == "/ci/nuclei-templates"
    assert "-silent" not in launches[0]
    assert observed[0][0] == 23  # 20% of execution range 10..75, after 600s.
    assert "40/200" in observed[0][1]
    assert scan.job.status == "finished" and scan.job.progress == 100


def test_no_stats_reports_waiting_without_inventing_progress(db, scan, monkeypatch):
    mock_scanner(monkeypatch, stats=["[INF] initializing templates"])
    observed = []
    monkeypatch.setattr(
        nucleiurl.time,
        "sleep",
        lambda seconds: observed.append((scan.job.progress, scan.job.message)),
    )
    nucleiurl.run_nucleiurl(db, scan.job)
    assert observed[0][0] == 10
    assert "statistics" in observed[0][1].lower()


def test_worker_rejects_handler_that_returns_without_terminal_status(db, monkeypatch):
    job = Job(plugin="dummy", status="running", progress=25)
    db.add(job)
    db.commit()
    monkeypatch.setattr(worker, "get_plugin", lambda name: lambda session, current: None)
    worker.process_job(db, job)
    assert job.status == "failed" and job.progress == 100
    assert "terminal" in job.message


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ({"url": "https://example.test/page", "location": "/login"}, "https://example.test/page"),
        (
            {"url": "https://example.test/", "final_url": "https://example.test/login"},
            "https://example.test/login",
        ),
        (
            {"url": "https://example.test/", "final-url": "https://other.test/"},
            "https://other.test/",
        ),
        ({"url": "https://example.test/", "final_url": "/login"}, "https://example.test/"),
        ({"input": "https://example.test/", "location": "/login"}, "https://example.test/"),
        ({"location": "/login"}, None),
    ],
)
def test_urlprobe_keeps_an_absolute_observed_url_not_location(record, expected):
    assert urlprobe.extract_final_url(record) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [("120ms", 0.12), ("150µs", 0.00015), ("2s", 2.0), ("0s", 0.0), (0, 0.0), ("NaN", None)],
)
def test_httpx_duration_is_converted_to_seconds(value, expected):
    assert urlprobe.parse_float(value) == expected


def test_urlprobe_success_clears_stale_reachability_and_preserves_zero_length(
    db, scan, domain, customer, monkeypatch
):
    stale = Url(
        customer_id=customer["id"],
        domain_id=domain["id"],
        url="https://example.test/stale",
        status_code=200,
    )
    db.add(stale)
    db.flush()
    db.add(UrlDetail(url_id=stale.id, status_code=200, title="Old observation"))
    db.commit()
    output = json.dumps(
        {
            "input": scan.url.url,
            "url": scan.url.url,
            "status_code": 204,
            "content-length": 0,
            "time": "120ms",
        }
    )
    monkeypatch.setattr(
        urlprobe.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, output, ""),
    )
    urlprobe.run_urlprobe(db, scan.job)
    db.expire_all()
    assert scan.job.status == "finished", scan.job.message
    assert db.query(UrlDetail).filter_by(url_id=stale.id).one().status_code is None
    assert stale.status_code is None
    detail = db.query(UrlDetail).filter_by(url_id=scan.url.id).one()
    assert detail.content_length == 0 and detail.response_time_seconds == 0.12
    assert nucleiurl.select_scan_urls(db, SimpleNamespace(**domain)) == [scan.url.url]


@pytest.mark.parametrize(
    "item",
    [
        None,
        [],
        {"request": "invalid"},
        {"response": [200]},
        {"url": "https://example.test/", "request": 1, "response": "invalid"},
    ],
)
def test_katana_tolerates_malformed_nested_records(item):
    from app.plugins.katana import extract_katana_url

    expected_url = item.get("url") if isinstance(item, dict) else None
    assert extract_katana_url(item) == (expected_url, "GET", None, None)


@pytest.mark.parametrize(
    "line",
    [
        '{"percent":"NaN","requests":1,"total":2}',
        '{"percent":101,"requests":1,"total":2}',
        '{"percent":-1,"requests":1,"total":2}',
        '{"percent":25,"requests":-1,"total":2}',
        '{"percent":25,"requests":"bad","total":2}',
    ],
)
def test_invalid_stats_do_not_create_fake_progress(tmp_path, line):
    log = tmp_path / "stats.log"
    log.write_text(line)
    assert nucleiurl.read_scan_stats(log) is None


def test_stats_tail_handles_large_noisy_log_and_partial_last_record(tmp_path):
    log = tmp_path / "stats.log"
    log.write_text(
        "x" * 20000 + '\n{"percent":"50","requests":"100","total":"200","matched":"2"}\n{"percent":'
    )
    assert nucleiurl.read_scan_stats(log) == {
        "percent": 50.0,
        "requests": 100,
        "total": 200,
        "matched": 2,
    }


def test_missing_scanner_fails_cleanly(db, scan, monkeypatch):
    monkeypatch.setattr(nucleiurl, "prepare_templates", lambda: Path("/ci/nuclei-templates"))

    def missing(*args, **kwargs):
        raise FileNotFoundError("synthetic missing nuclei binary")

    monkeypatch.setattr(nucleiurl.subprocess, "Popen", missing)
    nucleiurl.run_nucleiurl(db, scan.job)
    assert scan.job.status == "failed" and "FileNotFoundError" in scan.job.message


def test_timeout_escalates_to_kill_when_termination_is_ignored(db, scan, monkeypatch):
    calls, _ = mock_scanner(monkeypatch, timeout=True)
    original = nucleiurl.subprocess.Popen

    def launch(*args, **kwargs):
        process = original(*args, **kwargs)

        def wait(**wait_options):
            if "timeout" in wait_options:
                raise subprocess.TimeoutExpired("synthetic-nuclei", 10)
            return -9

        process.wait = wait
        return process

    monkeypatch.setattr(nucleiurl.subprocess, "Popen", launch)
    nucleiurl.run_nucleiurl(db, scan.job)
    assert scan.job.status == "failed" and "kill" in calls


def test_failed_urlprobe_does_not_clear_unobserved_previous_details(db, scan, monkeypatch):
    monkeypatch.setattr(
        urlprobe.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 1, "", "synthetic httpx failure"
        ),
    )
    urlprobe.run_urlprobe(db, scan.job)
    db.expire_all()
    assert scan.job.status == "failed"
    assert db.query(UrlDetail).filter_by(url_id=scan.url.id).one().status_code == 200


@pytest.mark.parametrize("value", [1e-6, 1e-9, float("inf"), -1.0])
def test_numeric_httpx_duration_preserves_small_values_and_rejects_invalid(value):
    expected = value if 0 <= value < float("inf") else None
    assert urlprobe.parse_float(value) == expected


def test_stale_urlprobe_record_keeps_previous_metadata(db, scan, monkeypatch):
    detail = db.query(UrlDetail).filter_by(url_id=scan.url.id).one()
    detail.title = "Previous page title"
    detail.final_url = "https://example.test/previous"
    db.commit()
    monkeypatch.setattr(
        urlprobe.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", ""),
    )
    urlprobe.run_urlprobe(db, scan.job)
    db.expire_all()
    assert detail.status_code is None
    assert detail.title == "Previous page title"
    assert detail.final_url == "https://example.test/previous"
