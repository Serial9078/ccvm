# Backend quality checks and CI repair

Investigation date: 2026-11-01 (Europe/Berlin).
Base branch: `sprint-1.0.2-feature-architecture`.
Base commit: `6173b43ef02177ae706e68c2106a7a6547d88841`.

## Reproduced causes

The historical [CI run 29188742847](https://github.com/Serial9078/ccvm/actions/runs/29188742847)
failed at `black --check app`; Ruff was skipped and the frontend passed.
Expired job logs do not establish which formatter/linter versions ran in July.
The previous requirements did not pin Black or Ruff. The findings below were
reproduced directly from the base commit with Python 3.12.14, Black 26.10.1,
and Ruff 0.17.3.

Black required changes in seven application files:

- `backend/app/api/v1/discovery.py`
- `backend/app/api/v1/jobs.py`
- `backend/app/models/asset.py`
- `backend/app/models/customer.py`
- `backend/app/plugins/katana.py`
- `backend/app/plugins/registry.py`
- `backend/app/worker/main.py`

Ruff independently reported 34 application findings:

| Rule | Count | Resolution |
| --- | ---: | --- |
| B008 | 30 | Recognize only `fastapi.Depends` as dependency declaration metadata. |
| I001 | 2 | Sort the host-model import and remove an extra blank line in Katana's import block. |
| E501 | 1 | Black wraps the asset timestamp declaration to the configured 100 columns. |
| B007 | 1 | Rename the unused worker loop variable from `index` to `_index`. |

The full backend review also found eight unformatted migration files and 20
Ruff findings in Alembic (nine I001, eight E501, three F401). These are cleaned
up as formatting/import changes. The `app.models` import in `alembic/env.py`
is intentionally retained and annotated: it registers model tables in
`Base.metadata`. Removing that apparent unused import would change behavior.
The two unused imports in the empty initial migration are removed.

## Additional import failure

Importing `app.plugins.registry` failed with
`ModuleNotFoundError: No module named 'app.plugins.legacy'`. That module does
not exist in the base tree. The registry now imports the six existing handlers
from `app.worker.main`, where their implementations already live. Importing the
worker module does not start its guarded worker loop. Katana still resolves to
the separate hardened implementation in `app.plugins.katana`.

The new registry regression tests first failed during collection against the
old import and pass after this correction. Worker dispatch and scanner behavior
are otherwise unchanged; this repair does not wire the registry into the worker.

## CI changes

`backend/requirements-dev.txt` includes the unchanged runtime requirements and
pins Black 26.10.1, Ruff 0.17.3, pytest 9.2.0, and HTTPX 0.28.1. These pins make
formatter/linter and direct test-tool versions explicit; transitive packages
are not a complete dependency lock.

The backend job now:

1. Installs runtime/development requirements and runs `python -m pip check`.
2. Runs `black --check app alembic tests`.
3. Runs `ruff check app alembic tests`.
4. Runs `python -m pytest -q`.

Ruff and tests have an explicit condition requiring successful dependency
installation and a workflow that has not been cancelled. They run even if an
earlier quality check fails. Failures still fail the job; no
`continue-on-error` is used. Python 3.12 and the frontend job remain unchanged.

The configured line length stays 100 and the E/F/I/B rules remain selected.
Only FastAPI's deliberate dependency marker is registered through Ruff's
`extend-immutable-calls`; B008 remains active for other calls. See the
[official Ruff setting](https://docs.astral.sh/ruff/settings/#lint_flake8-bugbear_extend-immutable-calls)
and [FastAPI dependency declaration](https://fastapi.tiangolo.com/tutorial/dependencies/).

## Automated tests

The suite covers:

- Health and OpenAPI generation.
- Customer CRUD, omitted-field preservation, request validation, and missing-record responses.
- Asset creation/listing and URL deduplication, retrieval, and domain filtering.
- Required job targets and discovery queue creation without running a scanner.
- Empty dashboard serialization.
- Katana JSON extraction, domain boundaries, duplicate/noise filtering, and HTTPS timeout fallback.
- All seven registry handlers, normalized names, and unknown plugins.
- A single reachable Alembic revision head, inspected without applying migrations.

Before application imports, test configuration overrides even an inherited
`DATABASE_URL` with `sqlite://`. API tests create a fresh SQLite database in
memory per test, enable foreign keys, and override FastAPI's `get_db` dependency.
Test teardown closes the session, removes the override, and disposes the engine.
An automatic fixture blocks socket connections and scanner subprocesses;
Katana tests replace subprocess execution with controlled mocks.

These are a useful initial CI gate, not PostgreSQL integration or API security
hardening tests. They do not exercise external scanner binaries or execute
migration upgrades/downgrades.

## Local validation

| Check | Result |
| --- | --- |
| Clean installation using `requirements-dev.txt` | Passed under Python 3.12.14. |
| `python -m pip check` | Passed. |
| `black --check app alembic tests` | Passed; 76 Python files unchanged. |
| `ruff check app alembic tests` | Passed. |
| `python -m pytest -q` | 37 passed. |
| Import all discoverable application modules and the worker | Passed without opening a database connection or starting a worker. |
| `python -m compileall -q app` | Passed. |
| Frontend `npm ci --no-audit --no-fund` and `npm run build` | Passed locally under Node 24.22.1; CI retains Node 22. |
| `git diff --check` | Passed. |

Local Black execution uses `BLACK_NUM_WORKERS=1` because this execution
environment disallows Black's multiprocessing listener socket. This changes
parallelism only; CI uses the normal Black command on GitHub's runner.

A syntax-tree comparison of all 63 application files confirmed unchanged
executable logic after excluding the reviewed imports and unused-variable
rename. A separate comparison confirmed identical executable statements,
revision identifiers, and migration operations in all nine Alembic files,
excluding imports and module docstrings.

Two non-failing backend deprecation warnings remain: Pydantic's class-based
configuration in the existing customer schema and Starlette's use of the
AnyIO `BlockingPortal` alias. They are visible, not suppressed. The frontend
also retains its existing bundle-size warning (one minified chunk exceeds
500 kB). Dependency upgrades and bundle splitting are separate work.

## Reproduce

From a checkout of the repair branch:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
cd backend
python -m pip install -r requirements-dev.txt
python -m pip check
black --check app alembic tests
ruff check app alembic tests
python -m pytest -q
```

For formatting, run `black app alembic tests`; review Ruff suggestions with
`ruff check app alembic tests` before applying fixes. In particular, do not
remove intentional model-registration imports.

## Deployment boundary

No Docker deployment was built, restarted, or published. Dockerfiles,
`docker-compose.yml`, runtime requirements, and database configuration are
unchanged. No existing database was contacted or modified; no migration was
applied. Merge into the development branch and any later deployment remain
separate actions.
