"""Root-local interactive operator enrollment and recovery; never an HTTP API."""

import argparse
import fcntl
import getpass
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from contextlib import contextmanager
from urllib.parse import quote, urlsplit

from fastapi import HTTPException
from sqlalchemy import func, select, update
from sqlalchemy.exc import SQLAlchemyError

from app.database.session import SessionLocal
from app.models.auth import AuthSession, AuthUser
from app.services.auth_session import (
    auth_policy,
    create_operator,
    encrypt_totp,
    generate_totp_secret,
    hash_password,
    normalize_username,
    now,
    policy_directory,
    policy_path,
    validate_origin,
    validate_password,
    verify_totp,
)
from app.services.enrollment_qr import render_qr

ENROLLMENT_UI_VERSION = 2
MAX_PASSWORD_ATTEMPTS = 5
MAX_CODE_ATTEMPTS = 5
MAX_SETUP_COMMANDS = 15


def require_root():
    if os.geteuid() != 0:
        raise ValueError("Dieses lokale Verwaltungswerkzeug erfordert root")


def write_policy(origin):
    """Activate only a completely prepared account; never replace a policy."""
    require_root()
    validate_origin(origin)
    path = policy_path()
    policy_directory(create=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".auth-policy-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(
                json.dumps({"version": 1, "mode": "local", "origin": origin}).encode() + b"\n"
            )
            stream.flush()
            os.fsync(stream.fileno())
        try:
            # Same-directory hard link is an atomic no-clobber publication.
            os.link(temporary, path)
        except FileExistsError:
            current = auth_policy()
            if current is None or current.origin != origin:
                raise ValueError(
                    "Vorhandene Authentifizierungsrichtlinie wird nicht ersetzt"
                ) from None
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(temporary)


@contextmanager
def admin_lock():
    require_root()
    path = policy_path()
    policy_directory(create=True)
    descriptor = os.open(
        path.with_name("auth-admin.lock"), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("Ungültige lokale Verwaltungssperre")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("Ein anderer lokaler Verwaltungsvorgang läuft bereits") from error
        yield
    finally:
        os.close(descriptor)


def read_username():
    for _attempt in range(MAX_PASSWORD_ATTEMPTS):
        answer = input("Benutzername (Q = abbrechen): ").strip()
        if answer.casefold() == "q":
            raise KeyboardInterrupt
        try:
            return normalize_username(answer)
        except ValueError as error:
            print(f"Bitte korrigieren: {error}")
    raise ValueError("Zu viele ungültige Eingaben; es wurde nichts gespeichert")


def read_password(username):
    print("\n1/3 · Passwort festlegen")
    print("Passwörter bleiben beim Tippen unsichtbar. Der Bestätigungscode später ist sichtbar.")
    for _attempt in range(MAX_PASSWORD_ATTEMPTS):
        password = getpass.getpass("Neues Passwort (15–128 Zeichen): ")
        repeated = getpass.getpass("Passwort wiederholen: ")
        if password != repeated:
            print("Die Passwörter stimmen nicht überein. Bitte beide erneut eingeben.")
            continue
        try:
            validate_password(password, username)
            return password
        except ValueError as error:
            print(f"Bitte korrigieren: {error}")
    raise ValueError("Zu viele ungültige Passworteingaben; es wurde nichts gespeichert")


@contextmanager
def private_setup_screen():
    # A separate terminal screen prevents the QR/manual seed from remaining in
    # the ordinary scrollback on supported terminals. It cannot undo screenshots.
    terminal = os.environ.get("TERM", "")
    alternate = sys.stdout.isatty() and terminal.startswith(
        (
            "xterm",
            "screen",
            "tmux",
            "rxvt",
            "vte",
            "konsole",
            "alacritty",
            "kitty",
            "wezterm",
            "foot",
        )
    )
    if alternate:
        print("\x1b[?1049h\x1b[2J\x1b[H", end="", flush=True)
    try:
        yield alternate
    finally:
        if alternate:
            print("\x1b[0m\x1b[2J\x1b[H\x1b[?1049l", end="", flush=True)


def show_authenticator_qr(uri, username):
    print("\n2/3 · Authenticator verbinden")
    print(f"Konto: {username}")
    print("In deiner Authenticator-App ein Konto per QR-Code hinzufügen und hier scannen.")
    print("QR-Code und manuellen Schlüssel privat halten; keine Screenshots davon teilen.")
    try:
        qr = render_qr(uri)
        size = shutil.get_terminal_size(fallback=(80, 24))
        required_columns = max(80, qr.columns)
        if size.columns < required_columns or size.lines < qr.rows + 10:
            print(
                f"Terminal zum Scannen vergrößern: mindestens {required_columns} Spalten und "
                f"{qr.rows + 10} Zeilen. Danach R eingeben; mit M geht es manuell."
            )
            return
        print(qr.text, flush=True)
    except (UnicodeError, ValueError):
        print(
            "Der QR-Code kann hier nicht angezeigt werden. Mit M die manuelle Einrichtung wählen."
        )


def enrollment(username, origin):
    password = read_password(username)
    secret = generate_totp_secret()
    issuer = "CCVM " + urlsplit(origin).hostname
    uri = (
        f"otpauth://totp/{quote(issuer + ':' + username, safe='')}"
        f"?secret={secret}&issuer={quote(issuer, safe='')}&algorithm=SHA1&digits=6&period=30"
    )
    failures = 0
    with private_setup_screen() as alternate:

        def display():
            if alternate:
                print("\x1b[0m\x1b[2J\x1b[H", end="", flush=True)
            show_authenticator_qr(uri, username)
            print("3/3 · Verbindung bestätigen")
            print("Sechsstelligen Code sichtbar eingeben und Enter drücken.")
            print("M = manueller Schlüssel · R = QR erneut anzeigen · Q = abbrechen")

        display()
        for _command in range(MAX_SETUP_COMMANDS):
            answer = input("Bestätigungscode (sichtbar): ").strip()
            if answer.casefold() == "q":
                raise KeyboardInterrupt
            if answer.casefold() == "m":
                print("Manuelle Einrichtung: zeitbasiertes Konto, 6 Stellen, 30 Sekunden.")
                print(f"Einrichtungsschlüssel: {secret}")
                continue
            if answer.casefold() == "r":
                display()
                continue
            code = "".join(answer.split())
            step = verify_totp(secret, code) if re.fullmatch(r"[0-9]{6}", code) else None
            if step is not None:
                break
            failures += 1
            if failures >= MAX_CODE_ATTEMPTS:
                raise ValueError("Fünf ungültige Codes; Einrichtung beendet, nichts gespeichert")
            print(
                "Code ungültig. Denselben Authenticator-Eintrag verwenden und den nächsten "
                f"Code versuchen. Noch {MAX_CODE_ATTEMPTS - failures} Versuche."
            )
        else:
            raise ValueError("Einrichtung beendet: zu viele Eingaben; nichts gespeichert")
    print("Authenticator bestätigt. Einrichtung wird gespeichert …")
    return password, secret, step


def bootstrap(origin):
    validate_origin(origin)
    current = auth_policy()
    if current is not None and current.origin != origin:
        raise ValueError("Die vorhandene Richtlinie verwendet einen anderen HTTPS-Ursprung")
    with SessionLocal() as db:
        if db.scalar(select(func.count()).select_from(AuthUser)):
            raise ValueError("Ein Operator ist bereits vorhanden; bootstrap wird nicht wiederholt")
        print("CCVM-Konto einrichten · Mit Strg+C jederzeit abbrechen")
        username = read_username()
        password, secret, step = enrollment(username, origin)
        create_operator(db, username, password, secret, confirmed_step=step)
        db.commit()
    # Source publication is deliberately legacy until account enrollment and
    # its DB commit succeeded. Interrupted activation can use local 'activate'.
    write_policy(origin)
    print("VERIFIED: Lokale Anmeldung mit Passwort und Authenticator ist aktiviert.")
    print("Für die erste Anmeldung den nächsten neuen Authenticator-Code verwenden.")


def reset(username):
    policy = auth_policy()
    if policy is None:
        raise ValueError(
            "Keine aktive lokale Anmeldung; bei unterbrochener Einrichtung activate nutzen"
        )
    username = normalize_username(username)
    with SessionLocal() as db:
        user = db.scalar(select(AuthUser).where(AuthUser.username == username).with_for_update())
        if user is None:
            raise ValueError("Lokaler Operator wurde nicht gefunden")
        password, secret, step = enrollment(username, policy.origin)
        user.password_hash = hash_password(password)
        user.totp_ciphertext = encrypt_totp(username, secret)
        user.totp_last_step = step
        user.enabled = True
        user.updated_at = now()
        db.execute(update(AuthSession).values(revoked_at=now()))
        db.commit()
    print("VERIFIED: Passwort und Authenticator erneuert; alle Sitzungen wurden gesperrt.")
    print("Für die Anmeldung den nächsten neuen Authenticator-Code verwenden.")


def activate(origin):
    validate_origin(origin)
    with SessionLocal() as db:
        if not db.scalar(
            select(func.count()).select_from(AuthUser).where(AuthUser.enabled.is_(True))
        ):
            raise ValueError("Zuerst einen Operator mit bootstrap einrichten")
    write_policy(origin)
    print("VERIFIED: Vorbereitete lokale Anmeldung aktiviert.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    bootstrap_parser = commands.add_parser("bootstrap", help="Ersten lokalen Operator einrichten")
    bootstrap_parser.add_argument("--origin", required=True)
    reset_parser = commands.add_parser(
        "reset", help="Passwort/MFA lokal erneuern und Sitzungen sperren"
    )
    reset_parser.add_argument("--username", required=True)
    activate_parser = commands.add_parser(
        "activate", help="Unterbrochene Richtlinienaktivierung fortsetzen"
    )
    activate_parser.add_argument("--origin", required=True)
    args = parser.parse_args(argv)
    try:
        require_root()
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise ValueError(
                "Ein privates interaktives Terminal ist erforderlich; docker exec -it nutzen"
            )
        with admin_lock():
            if args.command == "bootstrap":
                bootstrap(args.origin)
            elif args.command == "reset":
                reset(args.username)
            else:
                activate(args.origin)
        return 0
    except (ValueError, HTTPException, OSError) as error:
        message = error.detail if isinstance(error, HTTPException) else str(error)
        print(f"STOPPED: {message}", file=sys.stderr)
        return 1
    except SQLAlchemyError:
        # SQL exceptions can carry parameter values; never print them here.
        print(
            "STOPPED: Datenbankzugriff fehlgeschlagen; private Konfiguration prüfen.",
            file=sys.stderr,
        )
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nSTOPPED: Lokale Einrichtung abgebrochen.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
