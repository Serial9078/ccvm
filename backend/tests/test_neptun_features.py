"""Preserve the deployed Neptun features without starting any scanners."""

from collections import Counter
from types import SimpleNamespace

import pytest

from app.api.v1 import url_screenshots
from app.database.deps import get_db
from app.main import app
from app.models.job import Job
from app.models.url import Url
from app.models.url_detail import UrlDetail
from app.models.url_screenshot import UrlScreenshot
from app.models.url_security import UrlSecurity
from app.plugins import headerprobe, katana, nucleiurl, registry
from app.worker import main as worker


@pytest.fixture
def db(client):
    yield from app.dependency_overrides[get_db]()


@pytest.mark.parametrize(
    "name", ["urlprobe", "headerprobe", "headerfindings", "screenshot", "nucleiurl"]
)
def test_new_plugins_resolve_without_worker_import_cycle(name):
    handler = registry.get_plugin(f" {name.upper()} ")
    assert handler is not None
    assert handler.__module__ == f"app.plugins.{name}"
    assert handler.__name__ == f"run_{name}"


def test_pipeline_listing_and_parent_validation(client, domain, db):
    pipeline = client.post("/api/v1/discover", json={"domain_id": domain["id"]}).json()
    jobs = db.query(Job).order_by(Job.id).all()
    jobs[0].status, jobs[0].progress = "finished", 100
    jobs[1].status, jobs[1].progress = "running", 50
    db.commit()
    result = client.get(f"/api/v1/pipelines/{pipeline['pipeline_id']}")
    assert result.status_code == 200
    data = result.json()
    assert data["total_jobs"] == 10
    assert data["finished_jobs"] == data["running_jobs"] == 1
    assert data["queued_jobs"] == 8
    assert data["status"] == "running"
    assert data["progress"] == 15
    assert data["domain_name"] == "example.test"
    assert client.get("/api/v1/pipelines").json() == [data]
    filtered = client.get("/api/v1/jobs", params={"pipeline_id": pipeline["pipeline_id"]})
    assert len(filtered.json()) == 10
    assert client.get("/api/v1/jobs", params={"pipeline_id": "missing"}).json() == []
    assert client.get("/api/v1/pipelines/missing").status_code == 404
    bad_parent = client.post("/api/v1/jobs", json={"plugin": "dummy", "parent_job_id": 9999})
    assert bad_parent.status_code == 404
    cross_pipeline = client.post(
        "/api/v1/jobs",
        json={"plugin": "dummy", "parent_job_id": jobs[0].id, "pipeline_id": "other"},
    )
    assert cross_pipeline.status_code == 400


def test_worker_waits_until_parent_finishes(client, domain, db):
    client.post("/api/v1/discover", json={"domain_id": domain["id"]})
    first = worker.claim_next_job(db)
    assert first.plugin == "subfinder" and first.status == "running"
    assert first.worker == worker.WORKER_NAME
    assert worker.claim_next_job(db) is None
    first.status = "finished"
    first.progress = 100
    db.commit()
    second = worker.claim_next_job(db)
    assert second.plugin == "dnsx" and second.parent_job_id == first.id
    assert worker.claim_next_job(db) is None


@pytest.mark.parametrize("status", ["failed", "skipped", "cancelled"])
def test_worker_skips_descendants_of_failed_parent(client, domain, db, status):
    client.post("/api/v1/discover", json={"domain_id": domain["id"]})
    jobs = db.query(Job).order_by(Job.id).all()
    jobs[0].status = status
    db.commit()
    assert worker.skip_blocked_jobs(db) == 9
    assert all(job.status == "skipped" and job.progress == 100 for job in jobs[1:])
    assert worker.claim_next_job(db) is None


def test_worker_records_unknown_plugin_and_handler_exception(db, monkeypatch):
    unknown = Job(plugin="not-registered", status="running")
    crashing = Job(plugin="dummy", status="running")
    db.add_all([unknown, crashing])
    db.commit()
    worker.process_job(db, unknown)
    assert unknown.status == "failed" and "Unknown plugin" in unknown.message

    def fail_handler(session, job):
        raise RuntimeError("controlled failure")

    monkeypatch.setattr(worker, "get_plugin", lambda name: fail_handler)
    worker.process_job(db, crashing)
    assert crashing.status == "failed" and "controlled failure" in crashing.message
    assert crashing.progress == 100


def test_url_intelligence_routes_and_nullable_security_score(client, customer, domain, db):
    response = client.post(
        "/api/v1/urls",
        json={
            "customer_id": customer["id"],
            "domain_id": domain["id"],
            "url": "https://example.test",
        },
    )
    url_id = response.json()["id"]
    detail = UrlDetail(url_id=url_id, status_code=200, title="CI page")
    security = UrlSecurity(url_id=url_id, security_score=None, error="Request timed out")
    screenshot = UrlScreenshot(
        url_id=url_id, filename="ci.png", screenshot_path="/screenshots/ci.png"
    )
    db.add_all([detail, security, screenshot])
    db.commit()
    result = client.get("/api/v1/url-details", params={"url_id": url_id})
    assert result.status_code == 200 and result.json()[0]["title"] == "CI page"
    assert client.get(f"/api/v1/url-details/{detail.id}").status_code == 200
    assert client.get("/api/v1/url-details/99999").status_code == 404
    scores = client.get("/api/v1/url-security", params={"url_id": url_id})
    assert scores.status_code == 200 and scores.json()[0]["security_score"] is None
    assert client.get("/api/v1/url-security", params={"minimum_score": 1}).json() == []
    assert client.get(f"/api/v1/url-security/{security.id}").status_code == 200
    assert client.get("/api/v1/url-security/99999").status_code == 404
    images = client.get("/api/v1/url-screenshots", params={"url_id": url_id})
    assert images.status_code == 200 and images.json()[0]["filename"] == "ci.png"
    assert client.get("/api/v1/url-screenshots", params={"url_id": 9999}).json() == []


def test_screenshot_get_head_and_path_boundaries(client, tmp_path, monkeypatch):
    directory = tmp_path / "screenshots"
    directory.mkdir()
    monkeypatch.setattr(url_screenshots, "SCREENSHOT_DIRECTORY", directory)
    content = b"\x89PNG\r\n\x1a\nCI fixture"
    (directory / "ci.png").write_bytes(content)
    result = client.get("/api/v1/screenshots/ci.png")
    assert result.status_code == 200 and result.content == content
    assert result.headers["content-type"] == "image/png"
    result = client.head("/api/v1/screenshots/ci.png")
    assert result.status_code == 200 and result.content == b""
    assert client.get("/api/v1/screenshots/invalid.txt").status_code == 400
    assert client.get("/api/v1/screenshots/missing.png").status_code == 404
    outside = tmp_path / "outside.png"
    outside.write_bytes(content)
    (directory / "escape.png").symlink_to(outside)
    assert client.get("/api/v1/screenshots/escape.png").status_code == 400


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("HTTPS://Example.Test:443/a//index.html#section", "https://example.test/a"),
        ("http://example.test:80/a/?id=1#top", "http://example.test/a?id=1"),
        ("https://example.test:8443/", "https://example.test:8443/"),
        ("//example.test/page", None),
        ("ftp://example.test/page", None),
        ("https://example.test:invalid/", None),
    ],
)
def test_katana_preserves_neptun_url_normalization(value, expected):
    assert katana.normalize_url(value) == expected


def test_katana_filters_static_resources_and_keeps_pages():
    assert not katana.should_collect_url("https://example.test/image.png")
    assert not katana.should_collect_url("https://example.test/a", "application/pdf")
    assert katana.should_collect_url("https://example.test/login", "text/html; charset=utf-8")


def test_failed_header_probe_is_unknown_instead_of_zero_score():
    result = headerprobe.build_result(1, "https://example.test", None, {}, "timeout")
    assert result["security_score"] is None and result["missing_headers"] is None
    result = headerprobe.build_result(1, "http://example.test", 200, {}, None)
    assert result["security_score"] == 0 and "Content-Security-Policy" in result["missing_headers"]


def test_nuclei_url_selection_respects_limits_and_skips_static_errors(domain, customer, db):
    for index in range(65):
        hostname = "example.test" if index < 30 else f"sub{index}.example.test"
        record = Url(
            customer_id=customer["id"],
            domain_id=domain["id"],
            url=f"https://{hostname}/page/{index}",
        )
        db.add(record)
        db.flush()
        db.add(UrlDetail(url_id=record.id, status_code=200, content_type="text/html"))
    for path, status, content_type in [
        ("image.png", 200, "image/png"),
        ("error", 500, "text/html"),
    ]:
        record = Url(
            customer_id=customer["id"], domain_id=domain["id"], url=f"https://example.test/{path}"
        )
        db.add(record)
        db.flush()
        db.add(UrlDetail(url_id=record.id, status_code=status, content_type=content_type))
    db.commit()
    targets = nucleiurl.select_scan_urls(db, SimpleNamespace(id=domain["id"]))
    assert len(targets) == 40
    origins = Counter(nucleiurl.origin_from_url(target) for target in targets)
    assert max(origins.values()) <= 12
    assert all(not target.endswith(("image.png", "error")) for target in targets)
