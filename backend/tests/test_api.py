import pytest


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "app": "CCVM", "version": "3.6.0"}


def test_openapi_can_be_generated(client):
    response = client.get("/openapi.json")
    assert response.status_code == 200
    paths = response.json()["paths"]
    for path in ["/health", "/api/v1/customers", "/api/v1/jobs", "/api/v1/urls"]:
        assert path in paths


def test_customer_lifecycle_preserves_omitted_fields(client, customer):
    path = f"/api/v1/customers/{customer['uuid']}"
    assert client.get(path).json() == customer
    assert client.get("/api/v1/customers").json() == [customer]

    response = client.put(path, json={"name": "Updated customer"})
    assert response.status_code == 200
    updated = response.json()
    assert updated["name"] == "Updated customer"
    assert updated["company"] == "CI Company"
    assert updated["uuid"] == customer["uuid"]

    response = client.delete(path)
    assert response.status_code == 200
    assert response.json() == {"status": "deleted", "uuid": customer["uuid"]}
    assert client.get(path).status_code == 404
    assert client.get("/api/v1/customers").json() == []


@pytest.mark.parametrize("method", ["get", "put", "delete"])
def test_missing_customer_returns_404(client, method):
    kwargs = {"json": {"name": "Updated customer"}} if method == "put" else {}
    response = getattr(client, method)("/api/v1/customers/nonexistent", **kwargs)
    assert response.status_code == 404
    assert response.json()["detail"] == "Customer not found"


def test_customer_requires_name(client):
    assert client.post("/api/v1/customers", json={}).status_code == 422


def test_asset_round_trip(client, customer):
    response = client.post(
        "/api/v1/assets",
        json={"customer_id": customer["id"], "target": "https://example.test"},
    )
    assert response.status_code == 200
    asset = response.json()
    assert asset["customer_id"] == customer["id"]
    assert asset["target"] == "https://example.test"
    assert client.get("/api/v1/assets").json() == [asset]


def test_url_creation_is_idempotent_and_domain_filter_works(client, customer, domain):
    payload = {
        "customer_id": customer["id"],
        "domain_id": domain["id"],
        "url": "https://example.test/page",
    }
    first = client.post("/api/v1/urls", json=payload)
    duplicate = client.post("/api/v1/urls", json=payload)
    assert first.status_code == duplicate.status_code == 200
    assert first.json()["id"] == duplicate.json()["id"]

    other_domain = client.post(
        "/api/v1/domains",
        json={"customer_id": customer["id"], "name": "other.test"},
    )
    assert other_domain.status_code == 200
    other = client.post(
        "/api/v1/urls",
        json={**payload, "domain_id": other_domain.json()["id"], "url": "https://other.test"},
    )
    assert other.status_code == 200
    assert len(client.get("/api/v1/urls").json()) == 2
    response = client.get("/api/v1/urls", params={"domain_id": domain["id"]})
    assert response.status_code == 200
    assert response.json() == [first.json()]
    assert client.get(f"/api/v1/urls/{first.json()['id']}").json() == first.json()
    assert client.get("/api/v1/urls/99999").status_code == 404


@pytest.mark.parametrize(
    ("plugin", "detail"),
    [
        ("katana", "domain_id is required for discovery jobs"),
        ("nuclei", "asset_id is required for scanner jobs"),
    ],
)
def test_job_requires_appropriate_target(client, plugin, detail):
    response = client.post("/api/v1/jobs", json={"plugin": plugin})
    assert response.status_code == 400
    assert response.json()["detail"] == detail
    assert client.get("/api/v1/jobs").json() == []


def test_discovery_only_queues_jobs(client, domain):
    response = client.post("/api/v1/discover", json={"domain_id": domain["id"]})
    assert response.status_code == 200
    jobs = response.json()["jobs"]
    assert [job["plugin"] for job in jobs] == ["subfinder", "dnsx", "httpx", "naabu", "katana"]
    assert all(job["status"] == "queued" and job["progress"] == 0 for job in jobs)
    assert all(job["domain_id"] == domain["id"] for job in jobs)
    assert len(client.get("/api/v1/jobs").json()) == 5


def test_discovery_rejects_missing_domain(client):
    response = client.post("/api/v1/discover", json={"domain_id": 99999})
    assert response.status_code == 404
    assert response.json()["detail"] == "Domain not found"


def test_empty_dashboard(client):
    response = client.get("/api/v1/dashboard")
    assert response.status_code == 200
    summary = response.json()
    assert summary["customers"] == summary["jobs"] == summary["findings"] == 0
    assert summary["latest_findings"] == summary["active_jobs"] == []
    assert summary["scanner_chart"] == []
