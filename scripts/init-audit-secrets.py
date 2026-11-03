#!/usr/bin/env python3
"""Create local-only vault/token files without displaying or overwriting secrets."""

import argparse
import base64
import os
import secrets
import stat
from pathlib import Path


def initialize(directory):
    directory = Path(directory)
    if directory.is_symlink():
        raise ValueError("Secret directory must not be a symlink")
    directory.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = directory.stat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ValueError("Secret directory must be owned by this user with mode 0700")
    files = [directory / name for name in ("vault.env", "operator.env")]
    if any(path.exists() or path.is_symlink() for path in files):
        raise ValueError("Existing secret files retained; refusing to overwrite or rotate keys")
    values = [
        "CCVM_AUDIT_VAULT_KEY=" + base64.b64encode(secrets.token_bytes(32)).decode() + "\n",
        "CCVM_AUDIT_OPERATOR_TOKEN=" + secrets.token_urlsafe(32) + "\n",
    ]
    # Exclusive create also protects against a file appearing after preflight.
    # Retain any partially created file on interruption; do not silently rotate.
    for path, value in zip(files, values, strict=True):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    try:
        files = initialize(args.directory)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Stopped: {error}. Retain any existing files.\n")
    for path in files:
        print(f"Private file created: {path}")
    print("Back up the vault key separately from the database. No secrets were displayed.")


if __name__ == "__main__":
    main()
