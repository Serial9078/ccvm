#!/usr/bin/env python3
"""Reconcile the reviewed Neptun source snapshot without changing running services."""

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


def git(root, *args, check=True):
    return subprocess.run(["git", "-C", str(root), *args], check=check, capture_output=True)


def digest(content):
    return hashlib.sha256(content).hexdigest()


def live_contract():
    # These endpoints expose application metadata only and do not execute get_db.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for route in ("/health", "/openapi.json"):
        with opener.open("http://127.0.0.1:8088" + route, timeout=10) as response:
            data = json.load(response)
        if route == "/health":
            if data.get("status") != "ok" or data.get("version") != "4.4.0":
                raise RuntimeError(
                    f"Expected running CCVM 4.4.0; got status={data.get('status')!r}, "
                    f"version={data.get('version')!r}"
                )
        else:
            expected = {
                "/api/v1/pipelines",
                "/api/v1/url-details",
                "/api/v1/url-security",
                "/api/v1/url-screenshots",
                "/api/v1/screenshots/{filename}",
            }
            if (
                data.get("info", {}).get("version") != "4.4.0"
                or not expected <= data.get("paths", {}).keys()
            ):
                raise RuntimeError("The running API does not expose the reviewed Neptun 4.4 routes")


def reconcile(root, target, manifest, apply=False, probe=live_contract):
    root = Path(root).resolve()
    if not re.fullmatch(r"[0-9a-f]{40}", target):
        raise RuntimeError("Target must be a full commit SHA")
    actual_root = Path(git(root, "rev-parse", "--show-toplevel").stdout.decode().strip()).resolve()
    if actual_root != root:
        raise RuntimeError("The supplied root is not the Git repository root")
    git_dir = Path(git(root, "rev-parse", "--absolute-git-dir").stdout.decode().strip())
    with (git_dir / "ccvm-reconcile.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        branch = git(root, "branch", "--show-current").stdout.decode().strip()
        if branch != manifest["branch"]:
            raise RuntimeError(f"Unexpected branch: {branch}")
        before = git(root, "rev-parse", "HEAD").stdout.decode().strip()
        if before not in {manifest["head"], target}:
            raise RuntimeError(
                f"Checkout changed since export: {before}; expected {manifest['head']}"
            )
        git(root, "merge-base", "--is-ancestor", manifest["ci_base"], target)
        if before == target:
            # Use the original source base so a repeated invocation still checks
            # every reconciled file instead of treating a dirty checkout as done.
            source_base = manifest["head"]
        else:
            source_base = before
        if git(root, "diff", "--cached", "--quiet", check=False).returncode:
            raise RuntimeError("Staged changes exist; no files were changed")
        if (git_dir / "index.lock").exists():
            raise RuntimeError("Another Git operation holds index.lock")
        for marker in (
            "MERGE_HEAD",
            "CHERRY_PICK_HEAD",
            "rebase-merge",
            "rebase-apply",
        ):
            if (git_dir / marker).exists():
                raise RuntimeError(f"Unfinished Git operation: {marker}")
        names = git(root, "diff", "--name-only", "--no-renames", "-z", source_base, target).stdout
        paths = [Path(name.decode()) for name in names.split(b"\0") if name]
        # Check the entire exported source, including files untouched by the
        # upstream diff, so edits made after collection are never assumed tested.
        for name, expected_hash in manifest["files"].items():
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise RuntimeError("Invalid snapshot path")
            local = root / relative
            incoming = git(root, "show", f"{target}:{name}", check=False)
            allowed_hashes = {expected_hash}
            if incoming.returncode == 0:
                allowed_hashes.add(digest(incoming.stdout))
            if (
                local.is_symlink()
                or not local.is_file()
                or digest(local.read_bytes()) not in allowed_hashes
            ):
                raise RuntimeError(f"Source changed since export: {relative}")
        untracked = git(root, "ls-files", "--others", "--exclude-standard", "-z").stdout
        for raw_name in untracked.split(b"\0"):
            if not raw_name:
                continue
            name = raw_name.decode()
            path = Path(name)
            if (
                name.startswith(
                    ("backend/app/", "backend/alembic/", "frontend/src/", "screenshot-service/")
                )
                and path.suffix in {".py", ".ts", ".tsx", ".js", ".jsx"}
                and name not in manifest["files"]
            ):
                raise RuntimeError(f"Additional source not present in reviewed export: {name}")
        for relative in paths:
            if relative.is_absolute() or ".." in relative.parts:
                raise RuntimeError("Invalid target path")
            # Configuration was deliberately omitted from the source export.
            if (
                relative.name.startswith(".env")
                or relative.name.startswith("docker-compose")
                or str(relative) == "frontend/default.conf"
            ):
                raise RuntimeError(
                    f"Target unexpectedly changes protected configuration: {relative}"
                )
            local = root / relative
            for parent in (local, *local.parents):
                if parent == root:
                    break
                if parent.is_symlink():
                    raise RuntimeError(f"Symlink in target path: {relative}")
            incoming = git(root, "show", f"{target}:{relative.as_posix()}", check=False)
            if incoming.returncode:
                raise RuntimeError(f"Deletion is outside this reconciliation: {relative}")
            incoming_hash = digest(incoming.stdout)
            if before == target:
                allowed = {incoming_hash}
            else:
                previous = git(root, "show", f"{before}:{relative.as_posix()}", check=False)
                previous_hash = digest(previous.stdout) if previous.returncode == 0 else None
                # Snapshot paths must match the export or target exactly. In
                # particular, do not silently accept reverting a local feature
                # back to its old repository version after the export.
                snapshot_hash = manifest["files"].get(relative.as_posix())
                allowed = {
                    incoming_hash,
                    snapshot_hash if snapshot_hash else previous_hash,
                }
            if local.exists():
                if not local.is_file() or digest(local.read_bytes()) not in allowed:
                    raise RuntimeError(f"File changed since the reviewed export: {relative}")
            elif (
                before == target
                or relative.as_posix() in manifest["files"]
                or git(
                    root,
                    "cat-file",
                    "-e",
                    f"{before}:{relative.as_posix()}",
                    check=False,
                ).returncode
                == 0
            ):
                raise RuntimeError(f"Expected source file is missing: {relative}")
        probe()
        print(
            f"Verified {len(paths)} target paths against export/target; running API is CCVM 4.4.0."
        )
        if before == target:
            print(f"Already reconciled: {target}")
            return None
        if not apply:
            print("Preflight complete. Use --apply to reconcile the reviewed source.")
            return None
        backup_root = git_dir / "ccvm-reconcile-backups"
        backup_root.mkdir(mode=0o700, exist_ok=True)
        backup = Path(tempfile.mkdtemp(prefix="before-", dir=backup_root))
        index = Path(git(root, "rev-parse", "--git-path", "index").stdout.decode().strip())
        if not index.is_absolute():
            index = root / index
        shutil.copy2(index, backup / "index")
        present = []
        for relative in paths:
            local = root / relative
            if local.exists():
                destination = backup / "files" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(local, destination)
                present.append(relative.as_posix())
        (backup / "state.json").write_text(
            json.dumps(
                {
                    "head": before,
                    "target": target,
                    "present": present,
                    "paths": [p.as_posix() for p in paths],
                },
                indent=2,
            )
        )
        (backup / "paths").write_bytes(b"\0".join(p.as_posix().encode() for p in paths) + b"\0")
        if (
            git(root, "rev-parse", "HEAD").stdout.decode().strip() != before
            or index.read_bytes() != (backup / "index").read_bytes()
        ):
            raise RuntimeError(f"Git state changed during preflight; backup: {backup}")
        changed = False
        try:
            changed = True
            git(
                root,
                "--literal-pathspecs",
                "restore",
                "--source",
                target,
                "--staged",
                "--worktree",
                f"--pathspec-from-file={backup / 'paths'}",
                "--pathspec-file-nul",
            )
            # Only move the branch after the fully checked paths and index are
            # installed. The soft reset does not reset unrelated working files.
            git(root, "reset", "--soft", target)
            git(root, "diff", "--cached", "--quiet")
            git(root, "diff", "--quiet", "HEAD", "--", *(p.as_posix() for p in paths))
            probe()
        except BaseException as error:
            if changed:
                for relative in paths:
                    local = root / relative
                    if relative.as_posix() in present:
                        shutil.copy2(backup / "files" / relative, local)
                    elif local.is_file():
                        local.unlink()
                shutil.copy2(backup / "index", index)
                current = git(root, "rev-parse", "HEAD").stdout.decode().strip()
                if current == target:
                    git(root, "update-ref", "HEAD", before, target)
                elif current != before:
                    raise RuntimeError(
                        f"Unexpected concurrent HEAD during rollback; inspect {backup}"
                    ) from error
            raise RuntimeError(
                f"Reconciliation failed and original files/index were restored. Backup: {backup}"
            ) from error
        print(f"CCVM reconciled: {target}\nBackup: {backup}")
        status = git(root, "status", "--short").stdout.decode()
        print("Remaining local configuration/data:\n" + (status or "(none)"))
        return backup


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="/opt/ccvm")
    parser.add_argument("--target", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    root = Path(args.root)
    manifest = json.loads(
        git(root, "show", f"{args.target}:scripts/neptun-source-manifest.json").stdout
    )
    reconcile(root, args.target, manifest, apply=args.apply)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"ABORT: {error}", file=sys.stderr)
        sys.exit(1)
