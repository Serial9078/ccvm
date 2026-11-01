# Isolated PostgreSQL migration integration

Investigation: 2026-11-01 (Europe/Berlin).
Base: `cb6979946e98512c556990ea306eb11caa28e2c8` on
`sprint-1.0.2-feature-architecture`, including the merged backend CI repair (#1).

The [Neptun reconciliation](neptun-integration.md) extends this gate to the
actual 4.4.0 sources: thirteen migrations, fifteen application tables, and
head `7f91c32a60d1`. Earlier validation results below retain their historical
commit/run context.

## What the job proves

The separate `postgres-migrations` job in `.github/workflows/ci.yml`:

1. Starts `postgres:16-alpine` as a GitHub Actions service, matching the
   PostgreSQL major version in the existing Compose file. It has no persistent
   volume, an automatically assigned host port, a health check, and a ten-minute
   job timeout. The service is removed by GitHub after the job.
2. Creates `ccvm_ci_<github.run_id>_<github.run_attempt>` through the service's
   `POSTGRES_DB`. Every run and retry gets a fresh database in a fresh instance.
   The `ccvm_ci` / `ccvm_ci_only` credentials are synthetic CI-only values.
3. Installs `requirements-dev.txt` and runs `pip check`. This already includes
   the pinned SQLAlchemy 2.0.36, psycopg2-binary 2.9.10, Alembic 1.14.0, and
   pytest dependencies; no runtime dependency change is required.
4. Runs the integration file explicitly with `--confcutdir=integration`.
   This keeps it separate from `tests/conftest.py`, which deliberately forces
   SQLite and blocks sockets/scanner subprocesses for all unit tests.
5. Checks the connected database identity, PostgreSQL major version, and the
   absence of all user tables, views, materialized views, foreign tables, and
   sequences before migration. A nonempty database fails without migration.
6. Executes `python -m alembic -c alembic.ini upgrade head` in a fresh process.
   This uses the repository's real `alembic/env.py` and all thirteen revisions,
   without `Base.metadata.create_all`, `stamp`, skipped revisions, precreated
   application tables, or swallowed migration errors.
7. Reads the actual version table through `MigrationContext` and compares it
   with the single head reported by `ScriptDirectory`. The current head is
   `7f91c32a60d1`. It also logs Alembic `current --verbose` and `heads --verbose`.
8. Compares the migrated schema with all fifteen ORM tables: table/column
   presence, PostgreSQL types and lengths, nullability, indexes, unique
   constraints, foreign keys, and server defaults. Primary-key columns are
   checked explicitly because Alembic autogeneration does not cover that check.
   Two exact existing `assets` server defaults (`environment='production'`,
   `criticality='medium'`) are accepted explicitly; no broad drift exclusion is
   used and those historical defaults are preserved.
9. Inserts disposable smoke-test records, verifies a native boolean and a
   timezone-aware timestamp, and checks PostgreSQL SQLSTATEs for overlong
   VARCHAR values (`22001`), duplicate domain names (`23505`), missing parent
   records (`23503`), and integer-to-boolean assignment (`42804`). Savepoints
   isolate expected failures and connection teardown rolls back the records.
10. Runs `upgrade head` again and repeats revision/schema checks to establish
    that upgrading an already-current empty-install schema is a no-op.

The existing backend job still runs every original regression test with its
SQLite isolation intact. Seventeen additional offline tests validate the CI
connection guard, including invalid IDs/ports, retry database separation, and
ignoring inherited production-style configuration. The unit-suite total is 76;
the separate PostgreSQL job runs one end-to-end integration test. The reconciliation adds 22 feature cases and ten standalone Git safeguard
tests; the original 37 cases remain. Black and Ruff also cover `integration`
and `scripts`.

## Isolation boundaries

The integration helper does not accept an arbitrary connection URL. It requires
`GITHUB_ACTIONS=true`, numeric run/attempt IDs, and the mapped service port. It
constructs the driver, loopback host/host address, test database name, and dummy
credentials internally. `DATABASE_URL`, `DB_*`, `PGHOSTADDR`, `PGSERVICE`, and a
caller-supplied test URL cannot select a target. Inherited `PG*` / `DB_*` variables
are removed before connecting, and Alembic receives an explicitly constructed
`DATABASE_URL` in a clean database-related environment.

Connection attempts time out after five seconds. Fixed PostgreSQL options limit
statements to thirty seconds and lock waits to five seconds; each Alembic
subprocess has a 120-second deadline. The job uses GitHub-hosted `ubuntu-latest`
with read-only repository permission. It references no GitHub secrets,
production connection values, SSH access, Compose commands, existing volumes,
or deployment commands. No PostgreSQL instance is started locally by this work.
These checks prevent accidental target reuse; environment markers alone are
not a security boundary against someone deliberately editing the workflow.

## Reproduced migration defect and minimal repair

The first integration commit deliberately ran the untouched migration chain.
[Run 41283222578](https://github.com/Serial9078/ccvm/actions/runs/41283222578)
failed on real PostgreSQL while the backend's original 37 tests and frontend
both passed:

```text
Running upgrade  -> 1449178d5497, initial schema
Running upgrade 1449178d5497 -> 88b89730c7a7, extend asset model
psycopg2.errors.UndefinedTable: relation "assets" does not exist
[SQL: ALTER TABLE assets ADD COLUMN name VARCHAR(255)]
```

The original `1449178d5497` revision contained only `pass`. Its five baseline
tables were never created by Alembic. This is a missing bootstrap schema on
both database dialects, not evidence of a PostgreSQL-specific application bug.
SQLite API tests had masked it by creating the current ORM schema directly.

Only that empty initial revision is repaired. Its static table definitions are
reconstructed from the models at
[`e269d50`](https://github.com/Serial9078/ccvm/commit/e269d50), the commit that
introduced Alembic: `customers`, `plugins`, `assets`, `scans`, and the original
`findings`. The historical `findings.scan_id` relationship and original column
types are required by subsequent migrations; using current ORM models here
would cause duplicate columns and incompatible migration operations.

An offline semantic comparison verified the reconstructed definitions against
those historical ORM models: all columns, compiled PostgreSQL types,
nullability, server defaults, primary keys, foreign keys, unique constraints,
and indexes match. No database connection was used for that comparison.
All eight revision IDs and their parent links are retained. The other seven
revision files and `alembic/env.py` are unchanged.

A new migration after the head could not repair bootstrap: the chain would fail
before reaching it. Filling the empty baseline is therefore necessary for a
real migration from an empty database. Alembic skips already-applied revisions,
so this does not replay the baseline on an already-versioned installation.
It is not an automatic adoption/repair procedure for an unversioned existing
schema; the integration guard refuses any existing user relations.

## SQLite / PostgreSQL differences

The later migrations perform ALTER COLUMN, named foreign-key removal, and
constraint creation. SQLite's limited ALTER TABLE support cannot validate this
PostgreSQL path, and the unit suite does not attempt to do so. PostgreSQL also
enforces VARCHAR lengths and native boolean assignments that SQLite commonly
accepts more loosely. The integration assertions verify those differences
against PostgreSQL itself instead of weakening constraints or rewriting
historical migrations for SQLite.

## Failure evidence

Pytest prints the exact Alembic command, exit code, revision progress, SQL error,
and traceback. First-upgrade and no-op-upgrade logs have distinct filenames.
Timeouts retain partial subprocess output. A `finally` block records a schema
snapshot even after a migration/schema assertion fails, when a connection is
still available. PostgreSQL transactional DDL may leave no tables after a failed
upgrade; that empty snapshot is meaningful evidence, not a diagnostic failure.

On failure, the workflow also prints the last 200 service log lines and an
in-container `psql` table/identity/version check. It does not assume that an
`alembic_version` table survived rollback. The artifact
`postgres-migrations-<run-id>-<attempt>` retains the JUnit report, Alembic logs,
and `schema.json` for seven days. Snapshots contain schema information only,
not application rows or credentials. No step uses `continue-on-error`.

## Validation evidence

- The unchanged migration chain failed on PostgreSQL in
  [run 41283222578](https://github.com/Serial9078/ccvm/actions/runs/41283222578),
  establishing that the integration check detects the missing baseline.
- After restoring the baseline,
  [run 41283389877](https://github.com/Serial9078/ccvm/actions/runs/41283389877)
  passed all three jobs at `cb42bfeaa710bbfe64a7ce8bb115f55354419dcd`.
  Its PostgreSQL log identifies server 16.15, database
  `ccvm_ci_41283389877_1`, all eight upgrades, head `05c7a5c03d2f`, all twelve
  application tables plus `alembic_version`, and one passing integration test.
- The backend job confirms 78 files accepted by Black, Ruff passed, and all
  54 offline tests passed. The original two deprecation warnings remain visible.
  The frontend install and production build also passed.
- A clean local virtual environment on Python 3.12.14 passed dependency
  installation, `pip check`, Black, Ruff, and all 54 offline tests. No local
  PostgreSQL service or existing deployment was used.
- Offline comparison with `e269d50` confirms the reconstructed initial schema
  matches the historical model definitions exactly. The remaining seven
  revisions, application code, dependency files, Dockerfiles, and Compose
  configuration have no diff from the base commit. `git diff --check` passed.

## Running checks

Offline checks from `backend/` remain safe on a developer machine:

```bash
python -m pip install -r requirements-dev.txt
python -m pip check
black --check app alembic tests integration
ruff check app alembic tests integration
python -m pytest -q
```

Push the branch or open its pull request to run the PostgreSQL job in GitHub
Actions. The integration entry point refuses ordinary local execution; do not
supply a production URL or run deployment Compose files to reproduce it.

This job validates fresh installation, revision/schema convergence, repeat
upgrade, and the listed native-type/constraint behavior. Populated-database
upgrades, downgrades, full PostgreSQL API coverage, scanners, and production
deployment are outside its scope. No existing PostgreSQL database or Docker
deployment was contacted, altered, restarted, or redeployed.
