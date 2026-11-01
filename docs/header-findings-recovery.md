# Long finding URLs and HeaderFindings recovery

HeaderFindings correlates existing URL intelligence without making network
requests. A discovered HTML URL longer than 1,024 characters previously caused
PostgreSQL `22001` when it was stored in `findings.matched_at`. The transaction
failed before the first origin checkpoint, leaving the last committed progress
at 10%. The worker then accessed the expired ORM attribute `job.id` before
rolling back, raising `PendingRollbackError` and leaving the job `running`.

Migration `d91e6a2f4c80`, following `bc64c6f0e217`, widens this column to `TEXT`.
Existing values, IDs, nullability, findings and scan relationships remain intact.
Both HeaderFindings and Nuclei URL imports retain complete matched URLs. The
worker captures the plain job ID before plugin execution, allowing its existing
failure handler to roll back and record `failed` after an unsuccessful flush.

The migration sets bounded lock and statement timeouts. Downgrade obtains an
exclusive table lock and explicitly refuses values exceeding 1,024 characters;
it never silently truncates URLs. PostgreSQL can truncate on explicit narrowing
casts, so a plain reverse type alteration is insufficient.

## Operator command

`scripts/update-header-findings.py --target FULL_MERGE_SHA --job ID:UUID` performs
read-only preflight; `--apply` activates the correction and selected retry. Run it
on Neptun from the pinned target through `git show TARGET:scripts/update-header-findings.py
| python3 - --target TARGET --job ID:UUID --apply`. No production IDs or UUIDs
belong in this repository.

Supported source states are the previously deployed commit
`47866568efe70538034c1a1611b8fdf80430e2ad` or the reviewed target. The remote
deployment branch must match that target. Private Compose and nginx files are
preserved. Additional application source edits, other active work, changed
pipeline dependencies or partially executed downstream stages stop the command.

The operator requires exactly the diagnosed HeaderFindings row (`running`, 10%,
its correlation message, full ID and UUID), seven finished parent stages and
two untouched queued descendants. It reuses the immutable Docker/Git maintenance
implementation from the previous reviewed commit, loaded from Git rather than
the working tree. The database identity check, same-image helper container,
cgroup pause and PostgreSQL custom-format backup follow the existing URL updater.

With the API closed and worker paused, it checks for open database transactions,
saves all row fingerprints and verifies the backup. After the schema upgrade,
every existing table must retain its row count and fingerprint. It reloads the
worker while the selected job still blocks its descendants, pauses the new
worker, and compares fingerprints again. A short transaction locks and rechecks
the complete backed-up pipeline before changing only the selected job to
`queued`. Its ID, UUID and pipeline relationships remain unchanged. The same
worker then runs HeaderFindings and releases Screenshot and NucleiURL normally.

Private snapshots, dump, configuration copies and the recovery journal live
under `.git`. A journal records retry intent before the database update. Once
intent is recorded, repeated invocation only verifies; it never enqueues another
retry after a lost response. If intent was recorded but the selected job remains
stuck, retain the backup and inspect the exact job state before manual recovery.
Unknown schema, changed fingerprints or an unconfirmed worker reload leave the
API closed. Failed transactional migration can restore code to the previous
commit only; the command never restores or downgrades a production database.

Verification checks the direct API and frontend proxy, reloads nginx once for
a stale upstream 502/503/504, and waits up to 90 seconds for the actual selected
HeaderFindings job to finish. Its final output reports the current downstream
states; scanner completion still requires observing those jobs. No new Discover
pipeline or dummy scan is created.

## Regression coverage

Offline tests exercise full long URLs, existing finding updates/reopening,
Nuclei deduplication, a real failed flush followed by worker recovery, and the
operator's identity, ordering, backup, rollback and duplicate-retry guards.
Disposable PostgreSQL 16 CI reproduces `22001` before migration, preserves all
rows across upgrade, verifies long HeaderFindings/Nuclei inserts and updates,
executes the exact selected-job retry transaction, rejects a changed snapshot,
and proves that downgrade refuses truncation. The Docker integration exercises
the migration using a helper while the application container remains paused.

References: [SQLAlchemy session rollback](https://docs.sqlalchemy.org/en/20/orm/session_basics.html#rolling-back)
and [PostgreSQL 16 character types](https://www.postgresql.org/docs/16/datatype-character.html).
