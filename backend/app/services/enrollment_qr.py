"""Offline, black-on-white QR rendering for the private terminal setup wizard.

Only the local administrative CLI imports this helper. No URI or enrollment
secret is sent to a QR service, a subprocess, a file, or a log.
"""

from dataclasses import dataclass

from app.vendor.qrcodegen import QrCode

QUIET_ZONE = 4
MAX_PAYLOAD_BYTES = 2048
QR_COLORS = "\x1b[30;107m"
RESET_COLORS = "\x1b[0m"
Matrix = tuple[tuple[bool, ...], ...]


@dataclass(frozen=True)
class TerminalQr:
    text: str
    columns: int
    rows: int


def encode_matrix(uri: str) -> Matrix:
    """Return QR modules with the full four-module white quiet zone."""
    if not isinstance(uri, str) or not uri or len(uri.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise ValueError("Die QR-Nutzlast ist leer oder zu groß")
    symbol = QrCode.encode_text(uri, QrCode.Ecc.MEDIUM)
    side = symbol.get_size() + 2 * QUIET_ZONE
    return tuple(
        tuple(symbol.get_module(x - QUIET_ZONE, y - QUIET_ZONE) for x in range(side))
        for y in range(side)
    )


def render_qr(uri: str) -> TerminalQr:
    """Use two square modules per terminal cell with explicit light background.

    Half blocks preserve the square module proportions of a typical monospace
    terminal. Each line resets colors so subsequent visible OTP input uses the
    terminal's normal theme. The odd final module row gets a white lower half.
    """
    matrix = encode_matrix(uri)
    side = len(matrix)
    glyphs = {(False, False): " ", (True, False): "▀", (False, True): "▄", (True, True): "█"}
    lines = []
    for y in range(0, side, 2):
        upper = matrix[y]
        lower = matrix[y + 1] if y + 1 < side else (False,) * side
        lines.append(
            QR_COLORS
            + "".join(glyphs[(top, bottom)] for top, bottom in zip(upper, lower, strict=True))
            + RESET_COLORS
        )
    return TerminalQr(text="\n".join(lines), columns=side, rows=len(lines))
