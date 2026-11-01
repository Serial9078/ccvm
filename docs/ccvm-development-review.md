# CCVM development review and scan reliability

Review date: 2026-11-01. Application base:
`e622ae6537a779e66f083acab444cdedcae921c6` on
`sprint-1.0.2-feature-architecture`. Corrections use the separate branch
`fix/scan-progress-url-intelligence` and target that development branch.

## Repository and integration state

`main` is the five-file Sprint 0.1 placeholder at `4a50d08`, without a CI
workflow. It is 41 commits behind the reviewed development head. Every published
branch reviewed here is an ancestor of that head; there is no separate unmerged
feature tip. Promoting the application to `main` is a separate release decision.

| Branches | Role and integration state |
| --- | --- |
| `main` | Initial health endpoint, static frontend and base Compose |
| `sprint-0.3-foundation`, `sprint-0.4-frontend-rebuild`, `sprint-0.4-phoenix` | Foundation/frontend milestones, included in the development head |
| `sprint-0.5-hydra`, `sprint-0.8-quality-foundation`, `sprint-1.0.1-assets-pro` | Customer grid, quality/docs and asset management, included |
| `sprint-1.0.2-feature-architecture` | API 4.4.0, twelve plugin handlers, ten-stage discovery pipeline |
| `fix/backend-ci-quality` | PR #1: CI repair, registry fix and initial isolated tests |
| `ci/postgresql-migrations` | PR #2: historical baseline restoration and PostgreSQL migration gate |
| `integrate/neptun-source-ci` | PR #3: reviewed 4.4 sources, URL intelligence, screenshots, dependencies |
| `fix/nuclei-domain-scope` | PR #4: original/effective URL domain checks and disabled Nuclei redirects |
| `ops/worker-recovery` | PR #5: selected-job operator recovery, no automatic startup repair |

The last pre-change [CI run 41295159159](https://github.com/Serial9078/ccvm/actions/runs/41295159159)
passed backend, PostgreSQL and frontend jobs. Its steps ran formatting, Ruff,
backend tests, reconciliation safeguards, native migrations and the frontend
build. The local starting baseline also passed 125 backend tests, ten Git
safeguard tests, `npm ci`, TypeScript/Vite build and Oxlint. No current TypeScript
compilation failure was reproduced on this application head.

## Components

| Component | Actual behavior in the reviewed source | Correction or boundary |
| --- | --- | --- |
| Docker Compose | `/opt/ccvm` bind mounts, PostgreSQL health gate, scanner worker image, frontend `dist` | Example now includes screenshot service, health dependency, worker endpoint and shared image storage read-only for the API. PostgreSQL volume identity is preserved. |
| FastAPI | API 4.4.0; customer, asset, discovery, pipeline and URL intelligence routes | Contracts retained. `/health` returns static metadata, not dependency readiness. |
| PostgreSQL / Alembic | Fifteen mapped application tables; thirteen migrations; head `7f91c32a60d1` | No migration/schema changes. CI extends native import coverage within the existing disposable, rolled-back fixture. |
| Redis | Compose service/startup dependency | No application Redis client or queue/cache usage found. Jobs live in PostgreSQL. |
| Worker | `FOR UPDATE OF jobs SKIP LOCKED`, parent dependencies, descendant skipping | A returning handler must leave a terminal status. Interrupted jobs still require deliberate operator handling. |
| Nuclei | Worker binary; forty URLs/domain, twelve/origin; twenty-minute deadline | Incomplete outcomes, import scope/deduplication and measured progress corrected. Standalone Nuclei container only runs `tail` and does not execute these jobs. |
| Katana | Bounded crawl, HTTP fallback, domain normalization/filtering, static filtering | Malformed nested request/response fields no longer crash extraction. Collection limits retained. |
| URL Intelligence | HTTPX details, headers, header findings and screenshot records | Effective URL interpretation, subsecond timings, zero lengths and stale reachability corrected. Previous metadata retained when reachability becomes unknown. |
| Screenshot service | Express/Playwright, internal port 3001, PNGs under `/data/screenshots` | Compose previously omitted service and shared storage. Synthetic nginx checks do not execute a browser. |
| Gotenberg | Standalone version 8 service on port 3000 | No application call or PDF report API found; report integration remains work. |
| React/Vite | MUI, React Query, Axios, TypeScript/Vite; polling inventories | Fixed API host removed; shared API/image base, nginx/dev proxy, Docker `npm ci`, excluded host build artifacts and patched dependency lock added. |

## Reproductions and fixes

Before core corrections, the first 29 regression cases produced **22 failures
and seven passes**, using synthetic data, in-memory SQLite, mocked scanner
processes and the worker's actual `autoflush=False` setting.

| Trigger | Previous behavior | Corrected behavior |
| --- | --- | --- |
| Nuclei exits 1, 2 or 137 with a valid result file | Finished because output existed | Failed/incomplete; valid partial findings retained |
| Nuclei hard timeout | Finished with a timeout suffix | Failed with deadline reason; terminate/kill escalation tested |
| Repeated Nuclei result with autoflush disabled | Multiple inserts bypass pending-row lookup | New insert flushed; subsequent lines update the same finding |
| Other customer's matching template/URL | Existing finding reassigned to current asset | Lookup includes asset ID; other customer's evidence untouched |
| Malformed JSON/metadata before a valid result | Crash, lost work or false success | Malformed records counted, valid evidence retained, import incomplete |
| Scanner reports 20% after 600 seconds | Progress inferred from fraction of deadline | Progress follows JSON scanner statistics; absent stats report waiting |
| Handler returns without terminal state | Job remains running indefinitely | Worker records terminal failure |
| HTTPX `location: /login` | Relative Location saved as effective URL | Only absolute observed/probed URL fields used; next hop is not treated as visited |
| HTTPX subsecond duration or zero bytes | Timing/zero length lost | Timing converted to seconds; zero preserved |
| Completed HTTPX pass no longer reports an old 200 | Stale URL remains eligible for Nuclei | Reachability unknown; previous title/URL/response metadata preserved |
| Katana nested metadata has wrong types | Attribute error | Invalid nested fields ignored; valid top-level URL retained |
| Frontend outside original host | Fixed private API host; API/image origins diverge | Same-origin `/api/v1` default; build override applies to API and images |

A zero-exit Nuclei scan with no findings remains successful. An incomplete scan
is not evidence that a target is free of vulnerabilities. Existing domain and
redirect guards remain in force.

## Checks

Local final validation: 173 backend cases (48 added), twelve frontend cases,
ten Git safeguard cases, Black/Ruff over 107 Python files, dependency consistency,
TypeScript/Vite default and configured builds, Oxlint, screenshot JavaScript
syntax and whitespace checks passed. The updated dependency lock reports zero
npm audit findings (including development dependencies). Native integration results are recorded in
the pull request after GitHub Actions completes.

Backend commands, from `backend`, in a Python 3.12 virtual environment:

```bash
python -m pip install -r requirements-dev.txt
python -m pip check
black --check --config pyproject.toml app alembic tests integration ../scripts
ruff check --config pyproject.toml app alembic tests integration ../scripts
python -m pytest -q
python -m unittest discover -s ../scripts/tests -v
```

Frontend commands, from `frontend`, using Node 22:

```bash
npm ci
npm test
npm run build
npm run lint
node tests/check-build.mjs dist /api/v1
```

CI also runs these integration checks:

- Existing PostgreSQL 16 migrations/schema/native constraint/maintenance checks,
  extended with URLProbe upserts/stale status invalidation and Nuclei duplicate
  imports, reopening and CVSS serialization under native types.
- Compose validation without starting application services; actual frontend
  Dockerfile build; API JSON, SPA fallback and screenshot GET/HEAD through that
  image against a synthetic backend on a fresh internal Docker network. Cleanup
  removes only the uniquely named test containers/network/image.
- A separate build with `VITE_API_URL=https://ccvm-ci.invalid/api/v1` and a check
  of the compiled override; no request to that reserved hostname.
- Existing screenshot-service JavaScript syntax check. No `continue-on-error`.

The local workspace has no Docker CLI/daemon; PostgreSQL and Docker integration
evidence therefore comes from GitHub Actions. Offline tests prohibit network
connections and scanner subprocesses. They do not scan real targets, connect to
existing databases or validate browser rendering. Backend deprecations, duplicate
screenshot OpenAPI operation warning and the Vite bundle warning remain visible.

## Frontend dependency findings

The original CI install reported fourteen npm findings: five moderate and nine
high. A separate production-only audit reported four high package findings
(Axios, follow-redirects and the React Router packages). The lockfile is updated
within the existing declared version ranges, including Axios 1.21.0,
follow-redirects 1.16.2, React Router 7.18.5 and Vite 8.3.5. No forced major
upgrade or advisory suppression is used. Unused ESLint and eslint-config-prettier
development entries were removed after confirming that the actual lint command
and configuration use Oxlint and contain no ESLint imports. This eliminates the
remaining minimatch advisory chain without overriding transitive major versions.
The final full npm audit reports zero findings. CI now blocks high/critical
frontend dependency advisories. This is dependency audit evidence, not a claim
that the application has no security defects.

## Configuration and release boundaries

Frontend requests default to `/api/v1` on its own origin. nginx proxies `/api/`
to the Compose backend. Vite development proxies to `http://127.0.0.1:8088`, with
shell variable `CCVM_DEV_API_TARGET` as an override. Set `VITE_API_URL` during a
frontend build or in `frontend/.env.local` for a separate API origin; the
Dockerfile also accepts that build argument. The API's CORS allowlist must permit
that browser origin. Vite settings are compiled into assets, not read from the
runtime container environment; see [Vite environment documentation](https://vite.dev/guide/env-and-mode).
Nuclei progress uses `-stats-json` and request counters documented in
[ProjectDiscovery's scan metrics](https://github.com/projectdiscovery/nuclei-docs/blob/main/docs/nuclei/get-started.md#scan-metrics).

No deployment, merge, service restart, production scan, database reset, data
cleanup or server access is performed here. Migrations, maintenance/reconciliation
commands and other CloudCollab projects are unchanged. The checked-in Compose is
an example topology, not a replacement for Neptun's private configuration. An
existing screenshot bind mount needs explicit reconciliation before adopting the
example volume; this PR does not move or replace existing screenshot storage.
Deployment requires explicit authorization and preservation of local settings.

## Next priorities

1. Reproducible staging Compose with pinned scanner/template versions and
   browser/scanner tests against controlled local fixtures. Current coverage
   proves orchestration/parsing, not live scanner capabilities or every upstream
   JSON variant.
2. Persistent worker heartbeats and visible interruption states. Do not infer
   orphaned jobs only from age or auto-fail every running job at startup.
3. Authentication, authorization and customer-aware server-side inventory joins
   before tenant access. Frontend finding association uses URL matching and is
   not an authorization boundary. Header-generated finding association also
   needs a separate tenant-scope review.
4. Optional-stage semantics for screenshots, empty target sets and partial
   probes. The current linear ten-stage dependency order is retained here.
5. Report selection/Gotenberg integration and bounded report jobs; decide whether
   Redis is needed before adding another queue implementation.
6. Measured frontend bundle splitting. The present large-bundle warning is a
   performance issue, not a compilation failure.
