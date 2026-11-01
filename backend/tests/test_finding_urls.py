"""Full URLs and failure recovery at the header-to-finding boundary."""

import json

import pytest
from sqlalchemy import Text

from app.database.deps import get_db
from app.main import app
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.job import Job
from app.models.url import Url
from app.models.url_detail import UrlDetail
from app.models.url_security import UrlSecurity
from app.plugins import headerfindings, nucleiurl
from app.worker import main as worker


@pytest.fixture
def db(client):
    yield from app.dependency_overrides[get_db]()


def test_header_findings_keep_complete_long_url_and_reopen_without_duplicates(
    domain, customer, db, client
):
    target = "https://example.test/" + "abap-source." * 700 + "?q=Grüße"
    asset = Asset(customer_id=customer["id"], target="https://example.test/")
    url = Url(customer_id=customer["id"], domain_id=domain["id"], url=target)
    job = Job(domain_id=domain["id"], plugin="headerfindings", status="running")
    db.add_all([asset, url, job])
    db.flush()
    db.add_all(
        [
            UrlDetail(url_id=url.id, content_type="text/html", final_url=target),
            UrlSecurity(url_id=url.id, checked_url=target, security_score=5),
        ]
    )
    db.commit()
    assert isinstance(Finding.__table__.c.matched_at.type, Text)

    worker.process_job(db, job)
    assert job.status == "finished" and job.progress == 100, job.message
    findings = db.query(Finding).all()
    assert len(findings) == len(headerfindings.HEADER_RULES)
    identities = {finding.id for finding in findings}
    for finding in findings:
        assert finding.matched_at == target
        assert json.loads(finding.raw_json)["representative_url"] == target
        finding.status = "fixed"
    db.commit()

    headerfindings.run_headerfindings(db, job)
    assert job.status == "finished" and "Reopened: 6" in job.message
    assert {finding.id for finding in db.query(Finding)} == identities
    assert all(finding.status == "open" for finding in db.query(Finding))
    assert all(row["matched_at"] == target for row in client.get("/api/v1/findings").json())

    result = {
        "template-id": "long-url-regression",
        "matched-at": target,
        "info": {"name": "Synthetic finding", "severity": "low"},
    }
    assert nucleiurl.import_nuclei_result(db, job, asset, result) == (True, False)
    assert nucleiurl.import_nuclei_result(db, job, asset, result) == (False, False)
    db.commit()
    finding = db.query(Finding).filter_by(scanner="nuclei-url").one()
    assert finding.matched_at == target
    assert finding.host == "https://example.test"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://Example.Test:443/" + "long-path/" * 700, "https://example.test"),
        ("https://Example.Test:8443/path?q=value", "https://example.test:8443"),
        ("example.test:8443", "example.test:8443"),
        ("192.0.2.1", "192.0.2.1"),
    ],
)
def test_nuclei_host_contains_origin_while_complete_match_stays_separate(value, expected):
    assert nucleiurl.extract_host({"host": value}, "https://other.test/path") == expected
    assert nucleiurl.extract_host({}, value) == expected


def test_worker_records_failed_flush_then_skips_children_and_processes_next_job(
    domain, customer, db, monkeypatch
):
    asset = Asset(customer_id=customer["id"], target="https://example.test/")
    job = Job(domain_id=domain["id"], plugin="headerfindings", status="running")
    db.add_all([asset, job])
    db.flush()
    child = Job(plugin="screenshot", parent_job_id=job.id, status="queued")
    db.add(child)
    db.flush()
    grandchild = Job(plugin="nucleiurl", parent_job_id=child.id, status="queued")
    following = Job(plugin="dummy", status="queued")
    db.add_all([grandchild, following])
    db.commit()
    job_id, asset_id = job.id, asset.id

    def fail_flush(session, current):
        current.progress, current.message = 10, "Correlating stored HTML URLs"
        session.commit()
        session.add(Finding(asset_id=asset_id, name=None))
        session.commit()  # Real constraint error expires even the job's primary key.

    monkeypatch.setattr(worker, "get_plugin", lambda name: fail_flush)
    worker.process_job(db, job)
    assert db.get(Job, job_id).status == "failed"
    assert job.progress == 100 and "IntegrityError" in job.message
    assert db.query(Finding).count() == 0
    assert worker.skip_blocked_jobs(db) == 2
    assert child.status == grandchild.status == "skipped"
    assert worker.claim_next_job(db).id == following.id

    def finish(session, current):
        current.status, current.progress = "finished", 100
        session.commit()

    monkeypatch.setattr(worker, "get_plugin", lambda name: finish)
    worker.process_job(db, following)
    assert following.status == "finished"
