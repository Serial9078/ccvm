"""Local enrollment is readable, retryable and does not silently disclose seeds."""

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app import auth_admin
from app.services import auth_session

SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
PASSWORD = "a synthetic private enrollment passphrase"
ORIGIN = "https://ccvm.example.test"
MOMENT = datetime(2026, 11, 8, 12, tzinfo=UTC)


@pytest.fixture
def enrollment(monkeypatch):
    generated = []
    rendered = []

    def generate():
        generated.append(SECRET)
        return SECRET

    def render(uri):
        rendered.append(uri)
        return SimpleNamespace(text="SYNTHETIC QR", columns=20, rows=3)

    monkeypatch.setattr(auth_session, "now", lambda: MOMENT)
    monkeypatch.setattr(auth_admin, "generate_totp_secret", generate)
    monkeypatch.setattr(auth_admin, "render_qr", render)
    monkeypatch.setattr(auth_admin.sys.stdout, "isatty", lambda: False)
    monkeypatch.setattr(auth_admin.getpass, "getpass", lambda prompt: PASSWORD)
    return SimpleNamespace(generated=generated, rendered=rendered)


def valid_code():
    return auth_session.totp_code(SECRET)


def invalid_code():
    step = int(MOMENT.timestamp()) // 30
    valid = {auth_session.totp_code(SECRET, value) for value in (step - 1, step, step + 1)}
    return next(f"{value:06d}" for value in range(10) if f"{value:06d}" not in valid)


def answers(monkeypatch, values):
    values = iter(values)
    monkeypatch.setattr("builtins.input", lambda prompt: next(values))


def test_wrong_code_can_be_corrected_without_regenerating_the_qr(enrollment, monkeypatch, capsys):
    answers(monkeypatch, [invalid_code(), valid_code()[:3] + " " + valid_code()[3:]])
    password, secret, step = auth_admin.enrollment("operator", ORIGIN)
    assert password == PASSWORD and secret == SECRET
    assert step == int(MOMENT.timestamp()) // 30
    assert enrollment.generated == [SECRET]
    assert len(enrollment.rendered) == 1
    output = capsys.readouterr().out
    assert "Denselben Authenticator-Eintrag" in output
    assert PASSWORD not in output and SECRET not in output and "otpauth://" not in output


def test_manual_seed_is_explicit_and_qr_redisplay_keeps_the_same_key(
    enrollment, monkeypatch, capsys
):
    answers(monkeypatch, ["m", "r", valid_code()])
    auth_admin.enrollment("operator", ORIGIN)
    output = capsys.readouterr().out
    assert output.count(SECRET) == 1
    assert "otpauth://" not in output
    assert enrollment.generated == [SECRET]
    assert len(enrollment.rendered) == 2 and len(set(enrollment.rendered)) == 1


def test_manual_display_does_not_reset_the_incorrect_code_limit(enrollment, monkeypatch):
    answers(monkeypatch, [value for _ in range(5) for value in ("m", invalid_code())])
    with pytest.raises(ValueError, match="Fünf ungültige Codes"):
        auth_admin.enrollment("operator", ORIGIN)
    assert enrollment.generated == [SECRET]


def test_commands_are_bounded_even_without_code_attempts(enrollment, monkeypatch):
    answers(monkeypatch, ["r"] * auth_admin.MAX_SETUP_COMMANDS)
    with pytest.raises(ValueError, match="zu viele Eingaben"):
        auth_admin.enrollment("operator", ORIGIN)
    assert enrollment.generated == [SECRET]


def test_explicit_abort_never_returns_ready_credentials(enrollment, monkeypatch):
    answers(monkeypatch, ["q"])
    with pytest.raises(KeyboardInterrupt):
        auth_admin.enrollment("operator", ORIGIN)


def test_password_mismatch_and_policy_failure_can_be_corrected(enrollment, monkeypatch, capsys):
    passwords = iter([PASSWORD, "different", "short", "short", PASSWORD, PASSWORD])
    monkeypatch.setattr(auth_admin.getpass, "getpass", lambda prompt: next(passwords))
    answers(monkeypatch, [valid_code()])
    assert auth_admin.enrollment("operator", ORIGIN)[0] == PASSWORD
    assert enrollment.generated == [SECRET]
    output = capsys.readouterr().out
    assert "beide erneut" in output and "15–128" in output
    assert PASSWORD not in output and "different" not in output


def test_invalid_username_can_be_corrected_without_starting_mfa(enrollment, monkeypatch, capsys):
    answers(monkeypatch, ["invalid user", "Operator"])
    assert auth_admin.read_username() == "operator"
    assert not enrollment.generated
    assert "Bitte korrigieren" in capsys.readouterr().out


def test_qr_display_failure_requires_explicit_manual_choice(enrollment, monkeypatch, capsys):
    def unavailable(_uri):
        raise UnicodeError("synthetic unsupported terminal")

    monkeypatch.setattr(auth_admin, "render_qr", unavailable)
    answers(monkeypatch, [valid_code()])
    auth_admin.enrollment("operator", ORIGIN)
    output = capsys.readouterr().out
    assert "Mit M die manuelle Einrichtung" in output
    assert SECRET not in output and "otpauth://" not in output


def test_short_terminal_gets_resize_hint_instead_of_a_truncated_qr(enrollment, monkeypatch, capsys):
    monkeypatch.setattr(
        auth_admin.shutil,
        "get_terminal_size",
        lambda **_kwargs: SimpleNamespace(columns=10, lines=8),
    )
    answers(monkeypatch, [valid_code()])
    auth_admin.enrollment("operator", ORIGIN)
    output = capsys.readouterr().out
    assert "Terminal zum Scannen vergrößern" in output
    assert "Danach R eingeben" in output
    assert "SYNTHETIC QR" not in output
    assert SECRET not in output


def test_unsupported_terminal_never_clears_the_ordinary_screen(enrollment, monkeypatch, capsys):
    monkeypatch.setattr(auth_admin.sys.stdout, "isatty", lambda: True)
    monkeypatch.setenv("TERM", "dumb")
    answers(monkeypatch, [valid_code()])
    auth_admin.enrollment("operator", ORIGIN)
    assert "\x1b[2J" not in capsys.readouterr().out
