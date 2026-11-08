"""Every registered API route must cross the activated session boundary."""

import base64
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from sqlalchemy.orm import sessionmaker

from app import main
from app.api.v1 import auth
from app.database.deps import get_db
from app.services import auth_session

PASSWORD = "synthetic long phrase for boundary testing"
ORIGIN = "https://testserver"


@pytest.fixture
def normal_login(client, customer, monkeypatch):
    db = next(main.app.dependency_overrides[get_db]())
    monkeypatch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"a" * 32).decode())
    monkeypatch.setenv(
        "CCVM_AUDIT_OPERATOR_TOKEN", "old-operator-token-never-valid-after-activation"
    )
    monkeypatch.setattr(auth_session, "auth_policy", lambda: auth_session.AuthPolicy(ORIGIN))
    monkeypatch.setattr(auth, "auth_policy", lambda: auth_session.AuthPolicy(ORIGIN))
    monkeypatch.setattr(auth_session, "SessionLocal", sessionmaker(bind=db.get_bind()))
    moment = datetime(2026, 11, 8, 12, 0, 0, tzinfo=UTC)
    monkeypatch.setattr(auth_session, "now", lambda: moment)
    secret = auth_session.generate_totp_secret()
    auth_session.create_operator(db, "inventory-admin", PASSWORD, secret)
    db.commit()
    client.base_url = httpx.URL(ORIGIN)
    client.headers.update({"Origin": ORIGIN, "X-CCVM-Request": "1"})
    return client, secret, moment


def sign_in(client, secret):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": "inventory-admin",
            "password": PASSWORD,
            "code": auth_session.totp_code(secret),
        },
    )
    assert response.status_code == 200, response.text
    return response


def test_every_registered_api_route_rejects_anonymous_and_old_bearer(client, monkeypatch):
    monkeypatch.setattr(main, "auth_enabled", lambda: True)
    checked = []

    def no_session(request):
        checked.append((request.method, request.url.path))
        raise HTTPException(status_code=401, detail="Sign in required")

    monkeypatch.setattr(main, "require_session", no_session)
    for route in main.app.routes:
        if not isinstance(route, APIRoute) or not route.path.startswith("/api/v1/"):
            continue
        if route.path in {"/api/v1/auth/login", "/api/v1/auth/session"}:
            continue
        path = route.path
        for parameter in route.param_convertors:
            path = path.replace("{" + parameter + "}", "1")
        for method in route.methods:
            response = client.request(
                method,
                path,
                headers={"Authorization": "Bearer historical-operator-token"},
            )
            assert response.status_code == 401, (method, path, response.text)
            if method != "HEAD":
                assert response.json() == {"detail": "Sign in required"}
            assert response.headers["cache-control"] == "no-store"
            assert checked[-1] == (method, path)
    # The assertion covers the pre-existing web, network, scan, and inventory APIs.
    assert len(checked) > 40
    assert ("GET", "/api/v1/customers") in checked
    assert ("GET", "/api/v1/host-audits") in checked
    assert ("POST", "/api/v1/auth/logout") in checked


@pytest.mark.parametrize("path", ["/api/v1/customers", "/api/v1/host-audits"])
def test_invalid_policy_never_falls_back_to_legacy_access(client, monkeypatch, path):
    def invalid_policy():
        raise HTTPException(status_code=503, detail="Authentication unavailable")

    monkeypatch.setattr(main, "auth_enabled", invalid_policy)
    response = client.get(path, headers={"Authorization": "Bearer legacy-token"})
    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"


def test_health_remains_independent_of_auth_and_database(client, monkeypatch):
    def broken_policy():
        pytest.fail("Health probe must not read authentication state")

    monkeypatch.setattr(main, "auth_enabled", broken_policy)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_session_enforcement_applies_before_legacy_mutations(client, customer, monkeypatch):
    monkeypatch.setattr(main, "auth_enabled", lambda: True)

    def reject_mutation(request):
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            raise HTTPException(status_code=403, detail="CSRF check failed")

    monkeypatch.setattr(main, "require_session", reject_mutation)
    response = client.post("/api/v1/customers", json={"name": "Must not be created"})
    assert response.status_code == 403
    assert client.get("/api/v1/customers").json() == [customer]


def test_real_login_restores_session_and_protects_old_routes(normal_login):
    client, secret, _moment = normal_login
    assert client.get("/api/v1/customers").status_code == 401
    login = sign_in(client, secret)
    cookie = login.headers["set-cookie"]
    assert all(
        value in cookie.lower() for value in ("secure", "httponly", "samesite=strict", "path=/")
    )
    assert PASSWORD not in login.text and secret not in login.text
    restored = client.get("/api/v1/auth/session")
    assert restored.status_code == 200
    assert restored.json() == login.json()
    assert client.get("/api/v1/customers").status_code == 200
    assert client.get("/api/v1/host-audits/credentials?customer_id=1").status_code == 200
    assert client.post("/api/v1/customers", json={"name": "Blocked"}).status_code == 403
    response = client.post(
        "/api/v1/customers",
        json={"name": "Authorized"},
        headers={"X-CSRF-Token": login.json()["csrf_token"]},
    )
    assert response.status_code == 200


def test_old_operator_token_never_substitutes_for_an_activated_session(normal_login):
    client, _secret, _moment = normal_login
    client.headers["Authorization"] = "Bearer old-operator-token-never-valid-after-activation"
    assert client.get("/api/v1/customers").status_code == 401
    assert client.get("/api/v1/host-audits/credentials?customer_id=1").status_code == 401


def test_logout_revokes_copied_cookie_and_requires_csrf(normal_login):
    client, secret, _moment = normal_login
    login = sign_in(client, secret)
    copied_cookie = client.cookies.get(auth_session.COOKIE_NAME)
    assert client.post("/api/v1/auth/logout").status_code == 403
    assert client.get("/api/v1/customers").status_code == 200
    response = client.post(
        "/api/v1/auth/logout", headers={"X-CSRF-Token": login.json()["csrf_token"]}
    )
    assert response.status_code == 204
    assert client.get("/api/v1/auth/session").json()["authenticated"] is False
    client.cookies.set(auth_session.COOKIE_NAME, copied_cookie)
    assert client.get("/api/v1/customers").status_code == 401


def test_idle_timeout_closes_private_and_legacy_routes(normal_login, monkeypatch):
    client, secret, moment = normal_login
    sign_in(client, secret)
    monkeypatch.setattr(auth_session, "now", lambda: moment + timedelta(minutes=31))
    assert client.get("/api/v1/customers").status_code == 401
    assert client.get("/api/v1/auth/session").json() == {"mode": "local", "authenticated": False}


def test_mutation_from_sibling_origin_is_rejected_even_with_correct_cookie_and_csrf(normal_login):
    client, secret, _moment = normal_login
    login = sign_in(client, secret)
    response = client.post(
        "/api/v1/customers",
        json={"name": "Blocked sibling site"},
        headers={
            "X-CSRF-Token": login.json()["csrf_token"],
            "Origin": "https://other.cloudcollab.de",
        },
    )
    assert response.status_code == 403


def test_auth_validation_response_does_not_echo_password_or_mfa_input(normal_login):
    client, _secret, _moment = normal_login
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "inventory-admin", "password": PASSWORD * 30, "code": "secret-code"},
    )
    assert response.status_code == 422
    assert PASSWORD not in response.text and "secret-code" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_login_origin_is_checked_before_body_validation(normal_login):
    client, _secret, _moment = normal_login
    client.headers.pop("Origin")
    response = client.post("/api/v1/auth/login", json={})
    assert response.status_code == 403
    assert response.headers["cache-control"] == "no-store"
