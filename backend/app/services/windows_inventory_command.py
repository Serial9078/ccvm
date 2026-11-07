"""Build the fixed read-only Windows collector launch without a long command line.

Only validated collection modes vary. The gzip payload is the repository
collector itself, not caller-provided PowerShell. No target, account or credential
value belongs in this module or its command arguments.
"""

import argparse
import base64
import gzip
import json
from pathlib import Path

EXECUTABLE = "powershell"
OPTIONS = ("-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand")
MAX_COMMAND_CHARACTERS = 8000
MAX_SOURCE_BYTES = 64 * 1024


class CommandLimitError(ValueError):
    """The fixed collector cannot fit its reviewed launch budget."""


def _fixed_command(source, mode):
    if not isinstance(mode, str) or mode not in {"connection", "inventory", "windows_updates"}:
        raise ValueError("Unsupported Windows collection mode")
    if not isinstance(source, bytes) or not source or len(source) > MAX_SOURCE_BYTES:
        raise CommandLimitError("Fixed Windows collector source exceeds its size budget")
    # Decode strictly before creating the command. The remote StreamReader also
    # rejects invalid UTF-8; compression must preserve every source byte.
    source.decode("utf-8")
    script = f"$ccvmMode = '{mode}'\n".encode() + source
    compressed = base64.b64encode(gzip.compress(script, mtime=0)).decode("ascii")
    bootstrap = (
        "$ErrorActionPreference='Stop';"
        f"$b=[Convert]::FromBase64String('{compressed}');"
        "$m=[IO.MemoryStream]::new($b,$false);"
        "$z=[IO.Compression.GZipStream]::new($m,[IO.Compression.CompressionMode]::Decompress);"
        "$r=[IO.StreamReader]::new($z,[Text.UTF8Encoding]::new($false,$true));"
        "try{& ([ScriptBlock]::Create($r.ReadToEnd()))}"
        "finally{$r.Dispose();$z.Dispose();$m.Dispose()}"
    )
    encoded = base64.b64encode(bootstrap.encode("utf-16-le")).decode("ascii")
    arguments = [*OPTIONS, encoded]
    # Keep below cmd.exe's documented 8191-character limit even when a server
    # ignores WINRS_SKIP_CMD_SHELL. Include the executable and every separator.
    if len(" ".join([EXECUTABLE, *arguments])) >= MAX_COMMAND_CHARACTERS:
        raise CommandLimitError("Fixed Windows collector launch exceeds its command-line budget")
    return EXECUTABLE, arguments


def build_command(mode):
    """Read the sibling collector and return its fixed executable/argument list."""
    filename = (
        "windows_update_inventory.ps1" if mode == "windows_updates" else "windows_inventory.ps1"
    )
    return _fixed_command(Path(__file__).with_name(filename).read_bytes(), mode)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode", choices=("connection", "inventory", "windows_updates"), required=True
    )
    args = parser.parse_args()
    executable, arguments = build_command(args.mode)
    print(json.dumps({"executable": executable, "arguments": arguments}))


if __name__ == "__main__":
    main()
