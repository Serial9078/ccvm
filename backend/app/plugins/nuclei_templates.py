"""Prepare an explicit, persistent template catalog before launching Nuclei."""

import fcntl
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

DEFAULT_DIRECTORY = Path(__file__).resolve().parents[2] / ".scanner-data" / "nuclei-templates"
DOWNLOAD_TIMEOUT_SECONDS = 120
IGNORE_FILENAME = ".nuclei-ignore"


def config_directory() -> Path:
    result = subprocess.run(
        ["nuclei", "-version"], capture_output=True, text=True, timeout=15, check=False
    )
    output = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr)
    match = re.search(r"Nuclei Config Directory:\s*([^\r\n]+)", output)
    if result.returncode or not match or not Path(match[1].strip()).is_absolute():
        raise RuntimeError("Could not determine the Nuclei configuration directory")
    return Path(match[1].strip())


def has_policy(path: Path) -> bool:
    return path.is_file() and bool(path.read_bytes().strip())


def copy_missing_policy(source: Path, target: Path) -> None:
    if has_policy(target):
        return
    if target.exists():
        raise RuntimeError(f"Existing Nuclei ignore policy is empty; preserved: {target}")
    if not has_policy(source):
        raise RuntimeError("Official Nuclei ignore policy is missing; scan refused")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".ignore-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(source.read_bytes())
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, target)  # Publish atomically without replacing a user policy.
        except FileExistsError:
            if not has_policy(target):
                raise RuntimeError("Nuclei ignore policy changed during preparation") from None
    finally:
        os.unlink(temporary)


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
    if (
        result.returncode
        or not loaded
        or "Could not read nuclei-ignore" in result.stderr
        or "Could not parse nuclei-ignore" in result.stderr
    ):
        raise RuntimeError(
            "Nuclei could not load the selected templates: "
            + error_summary(result.stdout, result.stderr)
        )
    return len(loaded)


def prepare_templates() -> Path:
    directory = Path(os.environ.get("NUCLEI_TEMPLATES_DIR", str(DEFAULT_DIRECTORY)))
    existing = directory.is_dir() and bool(yaml_count(directory))
    if directory.exists() and not existing:
        raise RuntimeError(
            f"Nuclei template directory exists but contains no YAML templates: {directory}"
        )
    local_policy = config_directory() / IGNORE_FILENAME
    bundled_policy = directory / IGNORE_FILENAME
    for policy in (local_policy, bundled_policy):
        if policy.exists() and not has_policy(policy):
            raise RuntimeError(f"Existing Nuclei ignore policy is empty; preserved: {policy}")
    if existing and (has_policy(local_policy) or has_policy(bundled_policy)):
        copy_missing_policy(local_policy, bundled_policy)
        copy_missing_policy(bundled_policy, local_policy)
        return directory
    directory.parent.mkdir(parents=True, exist_ok=True)
    # A failed download stays outside the active catalog. Publish only a
    # complete successful install; never rewrite an existing template catalog.
    with (directory.parent / "nuclei-templates.install.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("A Nuclei template installation is already running") from error
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
            if not has_policy(local_policy):
                raise RuntimeError("Nuclei installer did not provide its official ignore policy")
            shutil.copyfile(local_policy, staging / IGNORE_FILENAME)
            if existing:
                # Upgrade catalogs provisioned before policy persistence. Keep
                # every existing template and restore only the missing policy.
                copy_missing_policy(staging / IGNORE_FILENAME, bundled_policy)
                return directory
            (staging / ".ccvm-catalog.json").write_text(json.dumps({"yaml_files": count}))
            staging.rename(directory)
    return directory
