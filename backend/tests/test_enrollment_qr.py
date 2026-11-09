"""QR geometry and terminal output, with no real enrollment material."""

import pytest

from app.services.enrollment_qr import (
    MAX_PAYLOAD_BYTES,
    QR_COLORS,
    QUIET_ZONE,
    RESET_COLORS,
    encode_matrix,
    render_qr,
)

URI = (
    "otpauth://totp/CCVM:synthetic-test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    "&issuer=CCVM&algorithm=SHA1&digits=6&period=30"
)
PIXELS = {" ": (False, False), "▀": (True, False), "▄": (False, True), "█": (True, True)}


def test_encoder_provides_square_immutable_matrix_and_full_white_quiet_zone():
    matrix = encode_matrix(URI)
    side = len(matrix)
    assert isinstance(matrix, tuple) and all(isinstance(row, tuple) for row in matrix)
    assert 21 + 2 * QUIET_ZONE <= side <= 177 + 2 * QUIET_ZONE
    assert all(len(row) == side and all(type(value) is bool for value in row) for row in matrix)
    assert all(not any(row) for row in (*matrix[:QUIET_ZONE], *matrix[-QUIET_ZONE:]))
    assert all(not any(row[:QUIET_ZONE]) and not any(row[-QUIET_ZONE:]) for row in matrix)
    assert any(any(row) for row in matrix)


def test_terminal_half_blocks_reproduce_every_module_with_explicit_colors():
    qr = render_qr(URI)
    matrix = encode_matrix(URI)
    lines = qr.text.splitlines()
    assert qr.columns == len(matrix) and qr.rows == (len(matrix) + 1) // 2
    assert len(lines) == qr.rows
    recovered = []
    for line in lines:
        assert line.startswith(QR_COLORS) and line.endswith(RESET_COLORS)
        cells = line[len(QR_COLORS) : -len(RESET_COLORS)]
        assert len(cells) == qr.columns and set(cells) <= PIXELS.keys()
        halves = [PIXELS[cell] for cell in cells]
        recovered.extend([tuple(top for top, _ in halves), tuple(bottom for _, bottom in halves)])
    assert tuple(recovered[: qr.columns]) == matrix
    assert not any(recovered[-1])  # Odd QR height is padded with white, never dark.
    assert URI not in qr.text and "GEZDGNBVGY3TQOJQ" not in qr.text


@pytest.mark.parametrize("value", [None, b"value", "", "x" * (MAX_PAYLOAD_BYTES + 1)])
def test_invalid_payload_is_rejected_without_echoing_content(value):
    with pytest.raises(ValueError) as caught:
        encode_matrix(value)
    assert "x" * 20 not in str(caught.value)


def test_payload_limit_counts_utf8_bytes():
    with pytest.raises(ValueError):
        encode_matrix("ü" * (MAX_PAYLOAD_BYTES // 2 + 1))


def test_same_input_produces_the_same_qr_without_io():
    assert render_qr(URI) == render_qr(URI)
