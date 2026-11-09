# QR encoder provenance

- Project: Project Nayuki, QR Code generator library.
- Source: https://github.com/nayuki/QR-Code-generator
- Upstream commit: `bcfe1b018cec5f1f91b5705eca5bb4cdd34e9f8d`.
- Source file: [`python/qrcodegen.py`](https://github.com/nayuki/QR-Code-generator/blob/bcfe1b018cec5f1f91b5705eca5bb4cdd34e9f8d/python/qrcodegen.py).
- Original SHA-256: `9f4ed1dd201dcb92b1bc0d6e14f46c754bcff0ce48580c5d7e8ace8f6926c8ef`.
- License: MIT; the original copyright/license header is retained in the Python
  source and in `qrcodegen.LICENSE`.

The bundled algorithm is unchanged. Local mechanical changes are Black formatting,
splitting/sorting the standard-library imports, and a file-specific Ruff `E501`
pragma preserving the upstream documentation text. No global lint exclusion is
needed. The module uses only Python's standard library.

The local `enrollment_qr` adapter adds a four-module white quiet zone and draws
black modules on an explicit white ANSI background. DENSO WAVE documents the
four-module margin at https://www.qrcode.com/en/howto/code.html. Each character
contains two vertical modules, preserving square modules in ordinary monospace
terminals. The CLI checks the required terminal dimensions before display.

Verification includes unit tests and an independent `zbarimg` decode of the
actual terminal-rendered modules, not merely the encoder's original matrix.
The decoder is a CI/development tool only and is not a production dependency.
No QR provider, network request, or runtime package download is used for setup.
