"""Independently decode synthetic terminal QR output with the native zbar tool.

Run from the backend directory after installing zbar-tools in the disposable CI
runner. Production enrollment needs neither this decoder nor any image library.
"""

import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote


def terminal_pixels(qr, colors, reset):
    glyphs = {" ": (False, False), "▀": (True, False), "▄": (False, True), "█": (True, True)}
    rows = []
    for line in qr.text.splitlines():
        assert line.startswith(colors) and line.endswith(reset)
        cells = line[len(colors) : -len(reset)]
        assert len(cells) == qr.columns
        halves = [glyphs[cell] for cell in cells]
        rows.extend([tuple(top for top, _ in halves), tuple(bottom for _, bottom in halves)])
    assert len(rows) == qr.rows * 2
    assert all(not any(row) for row in (*rows[:4], *rows[-4:]))
    assert all(not any(row[:4]) and not any(row[-4:]) for row in rows)
    return rows


def pbm_pixels(matrix, scale=6):
    width, height = len(matrix[0]) * scale, len(matrix) * scale
    raster = bytearray()
    for row in matrix:
        scaled = [value for value in row for _ in range(scale)]
        packed = bytearray((width + 7) // 8)
        for x, dark in enumerate(scaled):
            if dark:
                packed[x // 8] |= 1 << (7 - x % 8)
        raster.extend(packed * scale)
    return f"P4\n{width} {height}\n".encode("ascii") + raster


def main():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from app.services.enrollment_qr import QR_COLORS, RESET_COLORS, render_qr

    decoder = shutil.which("zbarimg")
    if decoder is None:
        raise RuntimeError("The independent QR check requires zbar-tools on the CI runner")
    cases = [
        ("CCVM", "synthetic-account"),
        ("CCVM ccvm.example.test", "Prüfgerät"),
        ("CCVM " + "a" * 120 + ".example.test", "u" * 128),
    ]
    for issuer, username in cases:
        # RFC 6238's published example secret is synthetic and not an account.
        uri = (
            f"otpauth://totp/{quote(issuer + ':' + username, safe='')}"
            "?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
            f"&issuer={quote(issuer, safe='')}&algorithm=SHA1&digits=6&period=30"
        )
        qr = render_qr(uri)
        pixels = terminal_pixels(qr, QR_COLORS, RESET_COLORS)
        result = subprocess.run(
            [decoder, "--quiet", "--raw", "-"],
            input=pbm_pixels(pixels),
            capture_output=True,
            timeout=20,
            check=False,
        )
        assert result.returncode == 0, "Native QR decoder did not recognize the terminal output"
        assert result.stdout.rstrip(b"\r\n") == uri.encode("utf-8")
    print(
        "VERIFIED: three local terminal QR codes independently decoded; "
        "Unicode and long labels passed"
    )


if __name__ == "__main__":
    main()
