"""Prepare an explicit, persistent template catalog before launching Nuclei."""

import fcntl
import json
import os
import subprocess
import tempfile
from pathlib import Path

DEFAULT_DIRECTORY = Path(__file__).resolve().parents[2] / ".scanner-data" / "nuclei-templates"
DOWNLOAD_TIMEOUT_SECONDS = 120


def error_summary(stdout: str, stderr: str, limit: int = 450) -> str:
    lines = [line.strip() for line in (stderr + "\n" + stdout).splitlines() if line.strip()]
    for marker in ("[FTL]", "[ERR]"):
        important = [line for line in lines if marker in line]
        if important:
            return " | ".join(important)[-limit:]
    messages = [line for line in lines if not line.startswith("{")]
    return " | ".join(messages[-3:])[-limit:] or "Scanner returned no diagnostic message"


def yaml_count(directory: Path) -> int:
    return sum(1 for path in directory.rglob("*.yaml") if path.is_file())


def selected_template_count(directory: Path, tags: str, severities: str) -> int:
    command = [
        "nuclei",
        "-t",
        str(directory),
        "-update-template-dir",
        str(directory),
        "-tags",
        tags,
        "-severity",
        severities,
        "-tl",
        "-disable-update-check",
        "-no-color",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
    loaded = [line.strip() for line in result.stdout.splitlines() if line.strip().endswith(".yaml")]
    if result.returncode or not loaded:
        raise RuntimeError(
            "Nuclei could not load the selected templates: "
            + error_summary(result.stdout, result.stderr)
        )
    return len(loaded)


def prepare_templates() -> Path:
    directory = Path(os.environ.get("NUCLEI_TEMPLATES_DIR", str(DEFAULT_DIRECTORY)))
    if directory.is_dir() and yaml_count(directory):
        return directory
    if directory.exists():
        raise RuntimeError(
            f"Nuclei template directory exists but contains no YAML templates: {directory}"
        )
    directory.parent.mkdir(parents=True, exist_ok=True)
    # A failed download stays outside the active catalog. Publish only a
    # complete successful install; never rewrite an existing template catalog.
    with (directory.parent / "nuclei-templates.install.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("A Nuclei template installation is already running") from error
        if directory.is_dir() and yaml_count(directory):
            return directory
        with tempfile.TemporaryDirectory(
            prefix=".nuclei-download-", dir=directory.parent
        ) as temporary:
            staging = Path(temporary) / "catalog"
            command = [
                "nuclei",
                "-update-templates",
                "-update-template-dir",
                str(staging),
                "-no-color",
            ]
            # -disable-update-check also disables template updates; use it only
            # for scans after this explicit preparation has succeeded.
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=DOWNLOAD_TIMEOUT_SECONDS,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                raise RuntimeError("Nuclei template download exceeded 120 seconds") from error
            count = yaml_count(staging) if staging.is_dir() else 0
            if result.returncode or not count:
                raise RuntimeError(
                    "Nuclei template installation failed: "
                    + error_summary(result.stdout, result.stderr)
                )
            (staging / ".ccvm-catalog.json").write_text(json.dumps({"yaml_files": count}))
            staging.rename(directory)
    return directory
