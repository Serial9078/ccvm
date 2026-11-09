"""Probe real terminal echo with synthetic MFA data; no DB or remote connections."""

import fcntl
import os
import pty
import select
import signal
import struct
import sys
import termios
import time
from datetime import UTC, datetime
from pathlib import Path

# Never inherit production database settings for this local terminal-only probe.
os.environ["DATABASE_URL"] = "sqlite://"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import auth_admin  # noqa: E402
from app.services import auth_session  # noqa: E402

SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
PASSWORD = "a synthetic private enrollment passphrase"
MOMENT = datetime(2026, 11, 8, 12, tzinfo=UTC)


def main():
    auth_session.now = lambda: MOMENT
    auth_admin.generate_totp_secret = lambda: SECRET
    step = int(MOMENT.timestamp()) // 30
    valid = auth_session.totp_code(SECRET)
    window = {auth_session.totp_code(SECRET, value) for value in (step - 1, step, step + 1)}
    invalid = next(f"{value:06d}" for value in range(10) if f"{value:06d}" not in window)
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 60, 160, 0, 0))
    pid = os.fork()
    if pid == 0:
        try:
            os.close(master)
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            for descriptor in (0, 1, 2):
                os.dup2(slave, descriptor)
            if slave > 2:
                os.close(slave)
            sys.stdin = os.fdopen(0, "r", encoding="utf-8", closefd=False)
            sys.stdout = os.fdopen(1, "w", encoding="utf-8", buffering=1, closefd=False)
            sys.stderr = os.fdopen(2, "w", encoding="utf-8", buffering=1, closefd=False)
            os.environ["TERM"] = "xterm"
            result = auth_admin.enrollment("synthetic-operator", "https://ccvm.example.test")
            assert result == (PASSWORD, SECRET, step)
            print("PTY ENROLLMENT OK", flush=True)
            os._exit(0)
        except BaseException:
            os._exit(1)
    os.close(slave)
    output = bytearray()
    reaped = False

    def receive(needle):
        mark = len(output)
        deadline = time.monotonic() + 10
        while needle not in output[mark:]:
            if time.monotonic() >= deadline:
                raise AssertionError("Terminal probe did not reach the expected prompt")
            ready, _, _ = select.select([master], [], [], 0.25)
            if ready:
                try:
                    block = os.read(master, 65536)
                except OSError:
                    raise AssertionError(
                        "Terminal probe exited before the expected prompt"
                    ) from None
                assert block, "Terminal probe closed unexpectedly"
                output.extend(block)

    try:
        receive(b"Neues Passwort (15")
        assert not termios.tcgetattr(master)[3] & termios.ECHO
        os.write(master, (PASSWORD + "\n").encode())
        receive(b"Passwort wiederholen")
        assert not termios.tcgetattr(master)[3] & termios.ECHO
        os.write(master, (PASSWORD + "\n").encode())
        receive(b"Best\xc3\xa4tigungscode (sichtbar):")
        assert termios.tcgetattr(master)[3] & termios.ECHO
        os.write(master, (invalid + "\n").encode())
        receive(b"Code ung\xc3\xbcltig")
        os.write(master, (valid + "\n").encode())
        receive(b"PTY ENROLLMENT OK")
        waited, status = os.waitpid(pid, 0)
        reaped = waited == pid
        assert os.waitstatus_to_exitcode(status) == 0
        captured = output.decode("utf-8")
        assert PASSWORD not in captured
        assert invalid in captured and valid in captured
        assert SECRET not in captured and "otpauth://" not in captured
        assert "\x1b[?1049h" in captured and "\x1b[?1049l" in captured
    finally:
        os.close(master)
        if not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
    print("VERIFIED: real PTY hides passwords, visibly echoes OTPs and retains QR on retry")


if __name__ == "__main__":
    main()
