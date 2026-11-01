"""URL identity must retain long scanner results and deduplicate per domain."""

import hashlib
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex

from app.database.deps import get_db
from app.main import app
from app.models.host import Host
from app.models.job import Job
from app.models.url import Url
from app.plugins import katana


def long_url():
    # Incompressible enough to exceed PostgreSQL's B-tree tuple limit even
    # after TOAST compression. Distinct tails must not be truncated away.
    token = "".join(hashlib.sha256(str(index).encode()).hexdigest() for index in range(160))
    return "https://example.test/search?token=" + token


@pytest.fixture
def db(client):
    yield from app.dependency_overrides[get_db]()


def row(customer, domain, url):
    return {"customer_id": customer["id"], "domain_id": domain["id"], "url": url}


def test_postgres_url_index_uses_a_fixed_size_sha256_key():
    indexes = [index for index in Url.__table__.indexes if index.unique]
    assert len(indexes) == 1
    ddl = str(CreateIndex(indexes[0]).compile(dialect=postgresql.dialect()))
    assert "sha256(" in ddl.lower()
    assert "domain_id" in ddl
    assert "uq_urls_domain_url_sha256" in ddl
    assert "uq_urls_domain_url" not in {constraint.name for constraint in Url.__table__.constraints}


def test_katana_upsert_targets_the_digest_index(db, domain, customer, monkeypatch):
    observed = []

    def capture(statement):
        observed.append(str(statement.compile(dialect=postgresql.dialect())))
        return SimpleNamespace(rowcount=1)

    monkeypatch.setattr(db, "execute", capture)
    assert katana.bulk_insert_urls(db, [row(customer, domain, long_url())]) == 1
    conflict = observed[0].split("ON CONFLICT", 1)[1]
    assert "domain_id" in conflict and "sha256(" in conflict
    assert "%" not in conflict  # Index inference cannot depend on bind parameters.


def test_bulk_import_preserves_long_urls_and_domain_identity(db, client, domain, customer):
    original = long_url()
    different = original[:-1] + ("0" if original[-1] != "0" else "1")
    rows = [row(customer, domain, url) for url in (original, original, different)]
    assert katana.bulk_insert_urls(db, rows) == 2
    assert katana.bulk_insert_urls(db, rows) == 0
    assert {record.url for record in db.query(Url)} == {original, different}
    other_customer = client.post("/api/v1/customers", json={"name": "Other Customer"}).json()
    other_domain = client.post(
        "/api/v1/domains", json={"customer_id": other_customer["id"], "name": "other.test"}
    ).json()
    assert katana.bulk_insert_urls(db, [row(other_customer, other_domain, original)]) == 1
    assert db.query(Url).count() == 3


@pytest.mark.parametrize("suffix", ["", "?q=Grüße/東京", r"?q=\xAB\123\\", "?q=a%2Fb&x=1"])
def test_api_and_orm_share_identity_and_retain_exact_text(db, client, domain, customer, suffix):
    original = long_url() + suffix
    response = client.post("/api/v1/urls", json=row(customer, domain, original))
    assert response.status_code == 200
    assert response.json()["url"] == original
    assert (
        client.post("/api/v1/urls", json=row(customer, domain, original)).json() == response.json()
    )
    record = db.get(Url, response.json()["id"])
    changed = original + "&updated=1"
    record.url = changed
    db.commit()
    assert katana.bulk_insert_urls(db, [row(customer, domain, changed)]) == 0
    assert katana.bulk_insert_urls(db, [row(customer, domain, original)]) == 1
    assert {entry.url for entry in db.query(Url)} == {changed, original}


def test_katana_long_url_import_finishes_job(db, domain, customer, monkeypatch):
    host = Host(
        customer_id=customer["id"], domain_id=domain["id"], hostname="example.test", alive=True
    )
    job = Job(domain_id=domain["id"], plugin="katana", status="running")
    db.add_all([host, job])
    db.commit()
    original = long_url()
    monkeypatch.setattr(
        katana,
        "collect_host_urls",
        lambda *args: (
            [
                {
                    "hostname": host.hostname,
                    "url": original,
                    "method": "GET",
                    "status_code": 200,
                    "content_type": "text/html",
                }
            ],
            0,
            0,
        ),
    )
    katana.run_katana(db, job)
    assert job.status == "finished", job.message
    assert job.progress == 100
    assert db.scalar(sa.select(Url.url)) == original
    assert "New URLs created: 1" in job.message
