# Explicit worker recovery

The worker processes one job at a time and does not automatically reclaim rows
left `running` after an interrupted execution. Such rows can block an operator's
idle-queue deployment check even when no scanner process remains.

`scripts/recover-worker.py` is an explicit maintenance command for the repository's
existing Compose topology. It requires a selected domain, each selected job's
numeric ID and full UUID, a pinned target commit, and `--apply` for changes.
Without `--apply`, preflight only reads Git, Docker, and the local API. Job IDs,
UUIDs, snapshots, process observations, and pilot records belong in the local
invocation and private backups; do not commit operational data to the repository.

The command refuses other queued/running jobs, unexpected processes or mounts,
unrelated incoming paths, unsupported Nuclei redirect flags, and stored targets
outside the selected domain. It requires an existing domain and customer asset.
Private Compose, nginx, environment, templates, and operator backup files may
remain in the working tree; unreviewed application source edits are refused.
The container names and application mount match the versioned Compose topology.
External worker processes or arbitrary Docker layouts are outside this command's
scope. It never rebuilds images, replaces Compose configuration, or runs Alembic.

Before stopping the existing worker it fsyncs a private snapshot of the selected
jobs under `.git/ccvm-worker-recovery-*`. It fast-forwards the reviewed source,
then uses the existing backend's application connection for a short transaction:
lock the selected rows with `NOWAIT`, recheck every backed-up field and the active
queue, and mark only selected `running` jobs `failed` with an interruption message.
Completed jobs are preserved. This operator action **does update job metadata in
the existing application database**; it is separate from CI's disposable database
checks. Findings, URLs, customers, credentials, and schema are not rewritten.
The host neither reads nor prints the backend's database credentials. The worker
restart is attempted in a `finally` block even after update or repair errors.
A failed transaction rolls back. A completed repair is retained in its private
backup/result files if a later verification fails; it is not automatically undone.

A new `dummy` job must finish within 45 seconds to prove that the worker actually
claims and completes work. With `--start-pipeline`, the command then starts one
ordinary active discovery pipeline for the selected domain and its subdomains,
saves its ID, and watches all ten stages for up to three hours. The pilot writes
normal application scan records; it is not a SQLite/CI test or a passive website
check. POST requests are never retried. Repeating the same target/domain command
with a saved pilot marker resumes monitoring without restarting or scanning again.
Interrupting monitoring does not cancel the pipeline. A lost start response leaves
the API queue as evidence and causes a later preflight to refuse duplicate work.

Thirty-three offline backend cases use synthetic IDs, UUIDs, domains, and Docker
responses. They cover transaction guards and rollback, snapshot mismatches,
other active work, preserved terminal jobs and scan data, private non-overwriting
backups, restart attempts on failures, scanner-process refusal, read-only preflight,
no POST retry, domain scope, and pilot resumption. A full local rehearsal combines
the actual in-memory API and repair transaction with mocked Docker/Git commands,
preserves synthetic private files, and creates only one pilot across repeated
invocations. No real worker or scanner runs in these tests.

The existing isolated PostgreSQL job also executes the exact repair payload using
savepoints, including native locking/timeouts and changed-snapshot refusal. Its
outer test transaction rolls all synthetic records back. CI never invokes the
operator command against an existing installation and never runs a real scanner.
