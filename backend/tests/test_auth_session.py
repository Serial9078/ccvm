"""Exercise real password/TOTP/cookie flows against a private SQLite database."""

import base64
import importlib.util
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import auth_admin
from app.api.v1.auth import router
from app.database.session import Base
from app.models.auth import AuthLoginLimit, AuthSession, AuthUser
from app.services import auth_session as auth

PASSWORD = "private synthetic test passphrase"
ORIGIN = "https://ccvm.example.test"


@pytest.fixture
def environment(monkeypatch, tmp_path):
    policy = tmp_path / "auth-policy.json"
    monkeypatch.setenv("CCVM_AUTH_POLICY_FILE", str(policy))
    monkeypatch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"a" * 32).decode())
    # CI runs without root. Production constant stays uid 0; only fixture-owned
    # policy files substitute their real owner in these isolated unit tests.
    monkeypatch.setattr(auth, "POLICY_OWNER_UID", os.geteuid())
    clock = [datetime(2026, 11, 8, 12, tzinfo=UTC)]
    monkeypatch.setattr(auth, "now", lambda: clock[0])
    engine = create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(
        engine, tables=[AuthUser.__table__, AuthSession.__table__, AuthLoginLimit.__table__]
    )
    monkeypatch.setattr(auth, "SessionLocal", factory)
    monkeypatch.setattr(auth_admin, "SessionLocal", factory)
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    @app.api_route("/private", methods=["GET", "POST"])
    def private(request: Request):
        principal = auth.require_session(request)
        assert auth.require_session(request) is principal
        return {"username": principal.username}

    with TestClient(app, base_url=ORIGIN) as client:
        yield SimpleNamespace(
            client=client, policy=policy, clock=clock, factory=factory, engine=engine
        )
    engine.dispose()


def activate(environment):
    environment.policy.write_text(json.dumps({"version": 1, "mode": "local", "origin": ORIGIN}))
    environment.policy.chmod(0o600)


def seed(environment, username="operator", password=PASSWORD):
    secret = auth.generate_totp_secret()
    with environment.factory() as db:
        user = auth.create_operator(db, username, password, secret)
        user_id = user.id
        db.commit()
    activate(environment)
    return user_id, secret


def login(environment, secret, **overrides):
    return environment.client.post(
        "/api/v1/auth/login",
        headers={"Origin": ORIGIN, "X-CCVM-Request": "1"},
        json={
            "username": "operator",
            "password": PASSWORD,
            "code": auth.totp_code(secret),
            **overrides,
        },
    )


def test_missing_policy_is_legacy_without_database_access(environment, monkeypatch):
    def forbidden():
        pytest.fail("Legacy session detection must not open a database")

    monkeypatch.setattr(auth, "SessionLocal", forbidden)
    assert not auth.auth_enabled()
    assert environment.client.get("/api/v1/auth/session").json() == {
        "mode": "legacy",
        "authenticated": False,
    }


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"version": True, "mode": "local", "origin": ORIGIN},
        {"version": 1, "mode": "legacy", "origin": ORIGIN},
        {"version": 1, "mode": "local", "origin": "http://ccvm.example.test"},
        {"version": 1, "mode": "local", "origin": ORIGIN + "/"},
        {"version": 1, "mode": "local", "origin": ORIGIN, "unexpected": True},
    ],
)
def test_present_invalid_policy_fails_closed(environment, payload):
    environment.policy.write_text(json.dumps(payload))
    environment.policy.chmod(0o600)
    assert environment.client.get("/api/v1/auth/session").status_code == 503
    with pytest.raises(HTTPException) as caught:
        auth.auth_enabled()
    assert caught.value.status_code == 503


def test_policy_rejects_symlink_permissions_owner_and_nonregular(environment, monkeypatch):
    activate(environment)
    environment.policy.chmod(0o644)
    assert environment.client.get("/api/v1/auth/session").status_code == 503
    environment.policy.chmod(0o600)
    monkeypatch.setattr(auth, "POLICY_OWNER_UID", os.geteuid() + 1)
    assert environment.client.get("/api/v1/auth/session").status_code == 503
    monkeypatch.setattr(auth, "POLICY_OWNER_UID", os.geteuid())
    target = environment.policy.with_suffix(".real")
    environment.policy.rename(target)
    environment.policy.symlink_to(target)
    assert environment.client.get("/api/v1/auth/session").status_code == 503
    environment.policy.unlink()
    environment.policy.mkdir()
    assert environment.client.get("/api/v1/auth/session").status_code == 503


def test_activation_directory_cannot_be_replaced_by_other_users(environment):
    # A writable parent would let another account remove a root600 policy and
    # select legacy mode. Fail closed even before the file is present.
    environment.policy.parent.chmod(0o777)
    assert environment.client.get("/api/v1/auth/session").status_code == 503
    environment.policy.parent.chmod(0o700)
    assert environment.client.get("/api/v1/auth/session").json()["mode"] == "legacy"


def test_policy_default_uses_dedicated_directory_and_missing_parent_is_legacy(
    environment, monkeypatch
):
    monkeypatch.delenv("CCVM_AUTH_POLICY_FILE")
    assert auth.policy_path().parts[-2:] == (".ccvm-auth", "auth-policy.json")
    monkeypatch.setenv(
        "CCVM_AUTH_POLICY_FILE", str(environment.policy.parent / "new" / "policy.json")
    )
    assert auth.auth_policy() is None


def test_policy_writer_is_atomic_no_clobber(environment, monkeypatch):
    monkeypatch.setattr(auth_admin, "require_root", lambda: None)
    auth_admin.write_policy(ORIGIN)
    before = environment.policy.read_bytes()
    auth_admin.write_policy(ORIGIN)
    assert environment.policy.read_bytes() == before
    with pytest.raises(ValueError, match="nicht ersetzt"):
        auth_admin.write_policy("https://another.example.test")
    assert environment.policy.read_bytes() == before
    assert not list(environment.policy.parent.glob(".auth-policy-*"))


def test_login_cookie_restore_csrf_logout_and_stolen_cookie_revocation(environment):
    _, secret = seed(environment)
    assert environment.client.get("/api/v1/auth/session").json() == {
        "mode": "local",
        "authenticated": False,
    }
    response = login(environment, secret)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["user"] == {"username": "operator"}
    assert body["authenticated"] and len(body["csrf_token"]) == 43
    cookie = response.headers["set-cookie"]
    assert "__Host-ccvm_session=" in cookie
    assert all(value in cookie for value in ("HttpOnly", "Secure", "SameSite=strict", "Path=/"))
    assert "Domain=" not in cookie
    raw = environment.client.cookies.get(auth.COOKIE_NAME)
    with environment.factory() as db:
        record = db.scalar(select(AuthSession))
        user = db.scalar(select(AuthUser))
        assert record.token_hash == auth.digest(raw)
        assert raw not in repr(record.__dict__)
        assert record.csrf_hash == auth.digest(body["csrf_token"])
        assert body["csrf_token"] not in repr(record.__dict__)
        assert PASSWORD not in repr(user.__dict__)
        assert secret.encode() not in user.totp_ciphertext
    assert environment.client.get("/api/v1/auth/session").json() == body
    assert environment.client.get("/private").json() == {"username": "operator"}
    assert environment.client.post("/private").status_code == 403
    headers = {"Origin": ORIGIN, "X-CCVM-Request": "1", "X-CSRF-Token": body["csrf_token"]}
    assert environment.client.post("/private", headers=headers).status_code == 200
    assert environment.client.post("/api/v1/auth/logout", headers=headers).status_code == 204
    environment.client.cookies.set(auth.COOKIE_NAME, raw, domain="ccvm.example.test", path="/")
    assert environment.client.get("/private").status_code == 401
    assert environment.client.get("/api/v1/auth/session").json()["authenticated"] is False


@pytest.mark.parametrize(
    "headers",
    [{}, {"Origin": ORIGIN}, {"Origin": "https://evil.example.test", "X-CCVM-Request": "1"}],
)
def test_login_requires_exact_origin_and_custom_header(environment, headers):
    _, secret = seed(environment)
    response = environment.client.post(
        "/api/v1/auth/login",
        headers=headers,
        json={"username": "operator", "password": PASSWORD, "code": auth.totp_code(secret)},
    )
    assert response.status_code == 403
    with environment.factory() as db:
        assert db.scalar(select(func.count()).select_from(AuthSession)) == 0


def test_https_required_even_with_forwarded_header(environment):
    seed(environment)
    environment.client.base_url = "http://ccvm.example.test"
    response = environment.client.get(
        "/api/v1/auth/session", headers={"X-Forwarded-Proto": "https"}
    )
    assert response.status_code == 403


def test_totp_is_required_and_consumed_once(environment):
    user_id, secret = seed(environment)
    assert login(environment, secret, code="000000").status_code == 401
    assert login(environment, secret).status_code == 200
    assert login(environment, secret).status_code == 401
    with environment.factory() as db:
        assert (
            db.get(AuthUser, user_id).totp_last_step == int(environment.clock[0].timestamp()) // 30
        )
        assert db.scalar(select(func.count()).select_from(AuthSession)) == 1
    environment.clock[0] += timedelta(seconds=30)
    assert login(environment, secret).status_code == 200


def test_wrong_account_and_password_have_same_generic_error(environment, monkeypatch):
    _, secret = seed(environment)
    seen = []
    original = auth.verify_password

    def verify(encoded, password):
        seen.append(encoded.startswith("$argon2id$"))
        return original(encoded, password)

    monkeypatch.setattr(auth, "verify_password", verify)
    unknown = login(environment, secret, username="missing")
    wrong = login(environment, secret, password="incorrect synthetic passphrase")
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()
    assert seen == [True, True]


def test_durable_account_throttle_blocks_even_correct_login_then_expires(environment):
    _, secret = seed(environment)
    for _ in range(5):
        assert login(environment, secret, password="wrong synthetic passphrase").status_code == 401
    blocked = login(environment, secret)
    assert blocked.status_code == 429
    assert blocked.headers["retry-after"] == "300"
    with environment.factory() as db:
        assert db.scalar(select(func.count()).select_from(AuthLoginLimit)) == 2
    environment.clock[0] += timedelta(minutes=5, seconds=1)
    assert login(environment, secret).status_code == 200


def test_ip_throttle_bounds_new_account_rows(environment):
    _, secret = seed(environment)
    for number in range(20):
        assert login(environment, secret, username=f"unknown{number}").status_code == 401
    with environment.factory() as db:
        before = db.scalar(select(func.count()).select_from(AuthLoginLimit))
    assert login(environment, secret, username="newunknown").status_code == 429
    with environment.factory() as db:
        assert db.scalar(select(func.count()).select_from(AuthLoginLimit)) == before


@pytest.mark.parametrize("expiry", ["idle", "absolute", "disabled"])
def test_server_side_session_limits(environment, expiry):
    user_id, secret = seed(environment)
    assert login(environment, secret).status_code == 200
    with environment.factory() as db:
        record = db.scalar(select(AuthSession))
        if expiry == "idle":
            record.last_seen_at = environment.clock[0] - auth.IDLE_TIMEOUT
        elif expiry == "absolute":
            record.expires_at = environment.clock[0]
        else:
            db.get(AuthUser, user_id).enabled = False
        db.commit()
    assert environment.client.get("/private").status_code == 401
    assert environment.client.get("/api/v1/auth/session").json()["authenticated"] is False


def test_csrf_not_accepted_from_other_session_and_bearer_is_not_a_session(environment):
    _, secret = seed(environment)
    first = login(environment, secret).json()
    environment.clock[0] += timedelta(seconds=30)
    assert login(environment, secret).status_code == 200
    headers = {"Origin": ORIGIN, "X-CCVM-Request": "1", "X-CSRF-Token": first["csrf_token"]}
    assert environment.client.post("/private", headers=headers).status_code == 403
    environment.client.cookies.clear()
    assert (
        environment.client.get(
            "/private", headers={"Authorization": "Bearer " + "a" * 64}
        ).status_code
        == 401
    )


def test_totp_ciphertext_is_bound_to_account_and_vault_key(environment, monkeypatch):
    user_id, secret = seed(environment)
    with environment.factory() as db:
        user = db.get(AuthUser, user_id)
        assert auth.decrypt_totp(user) == secret
        user.username = "other-operator"
        with pytest.raises(HTTPException) as caught:
            auth.decrypt_totp(user)
        assert caught.value.status_code == 503
        user.username = "operator"
        monkeypatch.setenv("CCVM_AUDIT_VAULT_KEY", base64.b64encode(b"b" * 32).decode())
        with pytest.raises(HTTPException):
            auth.decrypt_totp(user)


def test_rfc6238_totp_vector_and_clock_window(environment):
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert auth.totp_code(secret, step=1) == "287082"
    current = int(environment.clock[0].timestamp()) // 30
    assert auth.verify_totp(secret, auth.totp_code(secret, current - 1)) == current - 1
    assert auth.verify_totp(secret, auth.totp_code(secret, current + 2)) is None
    assert auth.verify_totp(secret, auth.totp_code(secret), last_step=current) is None


def test_bootstrap_is_private_interactive_and_one_time(environment, monkeypatch, capsys):
    monkeypatch.setattr(auth_admin, "require_root", lambda: None)
    monkeypatch.setattr(auth_admin.os, "geteuid", lambda: 0)
    # The lock itself is root-owned in production; test fixtures run as CI uid.
    monkeypatch.setattr(auth_admin, "admin_lock", __import__("contextlib").nullcontext)
    monkeypatch.setattr(auth_admin.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(auth_admin.sys.stdout, "isatty", lambda: True)
    secret = auth.generate_totp_secret()
    monkeypatch.setattr(auth_admin, "generate_totp_secret", lambda: secret)
    visible = iter(["Operator", auth.totp_code(secret)])
    monkeypatch.setattr("builtins.input", lambda prompt: next(visible))
    answers = iter([PASSWORD, PASSWORD])
    monkeypatch.setattr(auth_admin.getpass, "getpass", lambda prompt: next(answers))
    assert auth_admin.main(["bootstrap", "--origin", ORIGIN]) == 0
    output = capsys.readouterr().out
    assert PASSWORD not in output and secret not in output
    assert "otpauth://" not in output
    assert "Bestätigungscode später ist sichtbar" in output
    assert auth.auth_policy().origin == ORIGIN
    assert environment.policy.stat().st_mode & 0o777 == 0o600
    assert auth_admin.main(["bootstrap", "--origin", ORIGIN]) == 1
    assert "bereits vorhanden" in capsys.readouterr().err


def test_aborted_bootstrap_does_not_create_an_account_or_policy(environment, monkeypatch):
    monkeypatch.setattr(auth_admin, "require_root", lambda: None)
    monkeypatch.setattr(auth_admin, "admin_lock", __import__("contextlib").nullcontext)
    monkeypatch.setattr(auth_admin.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(auth_admin.sys.stdout, "isatty", lambda: False)
    # Call bootstrap directly: main deliberately refuses a non-TTY output.
    monkeypatch.setattr(
        "builtins.input", lambda prompt: "operator" if "Benutzername" in prompt else "q"
    )
    monkeypatch.setattr(auth_admin.getpass, "getpass", lambda prompt: PASSWORD)
    with pytest.raises(KeyboardInterrupt):
        auth_admin.bootstrap(ORIGIN)
    with environment.factory() as db:
        assert db.scalar(select(func.count()).select_from(AuthUser)) == 0
    assert not environment.policy.exists()


def test_local_reset_revokes_all_sessions_without_deleting_evidence(environment, monkeypatch):
    user_id, secret = seed(environment)
    assert login(environment, secret).status_code == 200
    next_secret = auth.generate_totp_secret()
    next_password = "new private synthetic passphrase"
    monkeypatch.setattr(
        auth_admin, "enrollment", lambda username, origin: (next_password, next_secret, -1)
    )
    auth_admin.reset("operator")
    assert environment.client.get("/private").status_code == 401
    assert login(environment, secret).status_code == 401
    assert login(environment, next_secret, password=next_password).status_code == 200
    with environment.factory() as db:
        assert db.get(AuthUser, user_id).enabled
        assert db.scalar(select(func.count()).select_from(AuthUser)) == 1


def test_aborted_reset_keeps_existing_mfa_password_and_session(environment, monkeypatch):
    user_id, secret = seed(environment)
    assert login(environment, secret).status_code == 200
    with environment.factory() as db:
        user = db.get(AuthUser, user_id)
        before = (user.password_hash, user.totp_ciphertext, user.totp_last_step)
    monkeypatch.setattr(auth_admin.getpass, "getpass", lambda prompt: PASSWORD)
    monkeypatch.setattr("builtins.input", lambda prompt: "q")
    with pytest.raises(KeyboardInterrupt):
        auth_admin.reset("operator")
    with environment.factory() as db:
        user = db.get(AuthUser, user_id)
        assert (user.password_hash, user.totp_ciphertext, user.totp_last_step) == before
    assert environment.client.get("/private").status_code == 200


def test_cli_refuses_noninteractive_or_unprivileged_enrollment(environment, monkeypatch, capsys):
    monkeypatch.setattr(auth_admin.os, "geteuid", lambda: 1000)
    assert auth_admin.main(["bootstrap", "--origin", ORIGIN]) == 1
    assert "root" in capsys.readouterr().err
    monkeypatch.setattr(auth_admin.os, "geteuid", lambda: 0)
    monkeypatch.setattr(auth_admin.sys.stdin, "isatty", lambda: False)
    assert auth_admin.main(["bootstrap", "--origin", ORIGIN]) == 1
    assert "interaktives Terminal" in capsys.readouterr().err
    assert not environment.policy.exists()


def test_auth_migration_is_additive_and_has_guarded_downgrade(environment, monkeypatch):
    migration_path = (
        Path(__file__).resolve().parents[1]
        / "alembic"
        / "versions"
        / "e7b5c9d2a401_add_local_operator_auth.py"
    )
    spec = importlib.util.spec_from_file_location("auth_migration_under_test", migration_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.down_revision == "d6a4b8e2f901"
    with environment.engine.begin() as connection:
        fake_op = SimpleNamespace(get_bind=lambda: connection)
        monkeypatch.setattr(module, "op", fake_op)
        connection.execute(
            AuthUser.__table__.insert(),
            {
                "username": "retained",
                "password_hash": "hash",
                "totp_ciphertext": b"cipher",
                "totp_last_step": -1,
                "enabled": True,
            },
        )
        with pytest.raises(RuntimeError, match="discard"):
            module.downgrade()
