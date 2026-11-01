# Neptun 4.4 source reconciliation

The source archive collected on 2026-11-01 contains a CCVM 4.4.0 application on
an uncommitted working tree based on `6173b43ef02177ae706e68c2106a7a6547d88841`.
The repository had already merged the backend CI repair and PostgreSQL gate at
`2dc39fbda8fc7cb035a2442b153f944d07d2c948`. Those checks covered the older
repository application, while Neptun had developed additional features locally.
A normal fast-forward could not preserve the overlapping uncommitted changes.

This reconciliation versions the deployed application sources while retaining
the CI fixes. The private Compose and nginx configuration, local environment,
operator backups, scanner templates, and runtime data were excluded from the
source export and are not replaced by this change.

## Preserved application

- The API remains version 4.4.0. Discovery creates ten dependent stages, including
  URL probing, header/security analysis, screenshots, and URL-targeted Nuclei.
- The registry resolves twelve handlers. Legacy handlers remain in the existing
  `app.plugins.legacy` module. Importing them from the former monolithic worker
  would conflict with the deployed worker, which now imports the registry.
- The worker retains parent dependency handling, failed-parent skipping,
  PostgreSQL job claiming, plugin dispatch, and its existing loop behavior.
- URL detail, security, screenshot, pipeline, and dashboard routes and schemas
  are retained. The frontend pipeline/URL/screenshot pages and navigation are
  preserved byte-for-byte from the export.
- The three screenshot-service source/build files are versioned as exported.
  This change does not start or rebuild that service or alter Compose files.

A syntax-tree comparison of every exported Python application file verified
unchanged executable statements, allowing only import ordering and renaming an
unused `index` variable to `_index` in the legacy handler. Formatting follows the
existing Black/Ruff rules and 100-column limit. First-party import classification
is explicit for `alembic`, `app`, and `integration` so the same checks work from
the backend directory and repository root. There is no new application behavior to activate,
so the reconciliation does not restart the backend, worker, frontend, or other
containers. The already-running 4.4.0 API contract is verified before and after
updating the checkout.

## Regression and PostgreSQL coverage

The original 37 regression cases are retained, with expectations updated for
the deployed API version, ten stages, twelve registry handlers, Katana's third
filter counter, canonical trailing slash, and relocated legacy handlers.
Domain-boundary cases follow the deployed collector's real order: normalize
and reject non-HTTP input first, then check the domain boundary. None of the
original cases are skipped or deleted.

Seventeen offline CI-isolation cases remain. Twenty-two additional feature
cases exercise registry import cycles, pipeline serialization/progress and
parent validation, job readiness, failed-parent propagation, worker failure
recording, URL intelligence filtering, nullable scores, screenshot GET/HEAD and
symlink boundaries, Katana canonicalization/static filtering, and Nuclei URL
selection limits. Total: **76 isolated backend cases**. Tests also block
`subprocess.Popen`, which the deployed Nuclei URL handler uses, in addition to
the existing network and `subprocess.run` restrictions.

Five exported Alembic revisions are retained with their original IDs, parents,
and operations, making thirteen upgrades in total. The single head is now
`7f91c32a60d1`, and the expected schema contains fifteen application tables.
The GitHub-only PostgreSQL service executes all thirteen revisions, verifies
head/schema convergence, and checks actual PostgreSQL persistence for job
parent claiming, nullable failed-probe scores, URL details, and screenshot and
security `ON CONFLICT` updates. All records are rolled back; no scanner runs.

[Run 41285939941](https://github.com/Serial9078/ccvm/actions/runs/41285939941)
validated application commit `caa880238d24c89c74f8f8aaf18f1243ad049677`:
all three jobs passed, including 76 backend cases, PostgreSQL 16.15 applying
all thirteen revisions and checking all fifteen tables, and the frontend
TypeScript/Vite build. Screenshot-service JavaScript syntax also passed locally.

Three existing backend warnings remain visible: Starlette/AnyIO's deprecated
alias, Pydantic's class-based configuration, and FastAPI's duplicate screenshot
operation ID for the existing combined GET/HEAD route. They are not suppressed
or changed as part of preserving the deployed application. The frontend's
existing bundle-size warning remains visible as well.

## Applying the reviewed source on Neptun

`scripts/neptun-source-manifest.json` records the original commit/branch, the
archive SHA-256, and SHA-256 fingerprints of all 172 exported source files. It
contains no source-export Git-status dump, environment values, or credentials.
`scripts/reconcile-neptun.py` consumes that manifest from an exact target commit.

1. Check the branch, original exported commit or already-applied target, CI-base
   ancestry, absence of staged changes, and absence of in-progress Git work.
2. Check all 172 exported files against the reviewed snapshot or target. Refuse
   edits or missing source files since collection, new unreviewed source files,
   untracked target-file collisions, symlinks, deletions, and any attempt to
   change `.env`, Compose files, or `frontend/default.conf`.
3. Read only `/health` and `/openapi.json` on `127.0.0.1:8088`, with proxies
   disabled, and require the existing 4.4.0 version and feature routes. Neither
   endpoint opens a database connection. The script sends no credentials.
4. Save every affected existing file, the original index, original HEAD, and a
   presence/path manifest under `.git/ccvm-reconcile-backups/before-*`, with a
   private directory and permission mask.
5. Restore only the checked target paths and index from the reviewed commit.
   Advance the branch with a soft ref move after those paths are installed.
   Unrelated local configuration/data are untouched; no stash or hard reset is
   used. The original untracked features become tracked at their reviewed form.
6. Check the index, installed target paths, and running API again. On an update
   or post-update health failure, restore original files, index, and HEAD from
   the backup. A repeated successful invocation verifies the target and exits
   without applying it again. Later edits are still detected.

The script performs no database reads/writes, Alembic execution, dependency
installation, Docker command, container restart, image build, or frontend build.
It preserves existing running services and frontend assets because application
behavior and frontend source match the deployed export. Private configuration
and excluded local data may correctly remain visible in `git status` afterward.
A refused precondition reports the concrete file or state; it does not discard
those changes or force an update.

Use a reviewed, merged full commit SHA as `TARGET`:

```bash
cd /opt/ccvm
git fetch origin sprint-1.0.2-feature-architecture
git show "$TARGET:scripts/reconcile-neptun.py" > /tmp/ccvm-reconcile.py
python3 /tmp/ccvm-reconcile.py --root /opt/ccvm --target "$TARGET" --apply
```

Without `--apply`, only preflight checks run. The checked-in command is not an
unattended updater: it deliberately targets one reviewed source snapshot.

## Reconciliation validation

Ten standalone tests use only disposable local Git repositories and stubbed
health probes. They cover successful reconciliation while preserving private
configuration and untracked data; dry-run behavior; changed/new source
protection; untracked collisions; staged-change refusal; health failure before
and after update; full file/index/HEAD rollback; repeat invocation; and protected
configuration refusal. They do not contact Neptun or execute scanner processes.

The actual 172-file Neptun export was also applied to an isolated temporary
clone of its original commit. The integration target installed successfully;
synthetic private Compose/nginx modifications and an excluded operator backup
were byte-for-byte unchanged. Repeating the operation was idempotent. This is
an offline rehearsal, not a claim that the real server has already been updated.

Run the extra checks from the repository root:

```bash
python3 -m unittest discover -s scripts/tests -v
black --check --config backend/pyproject.toml backend/app backend/alembic backend/tests backend/integration scripts
ruff check --config backend/pyproject.toml backend/app backend/alembic backend/tests backend/integration scripts
node --check screenshot-service/server.js
```

Downgrades, populated-database migration, live scanners/browser execution,
full scanner security review, and adopting private deployment configuration are
outside this reconciliation. The exported migrations are tested only against
fresh GitHub Actions PostgreSQL instances; no existing database was accessed.
