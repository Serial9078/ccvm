# Long Katana URL import correction

Katana job 109 on Neptun failed while inserting crawler results because the
`uq_urls_domain_url` unique B-tree index stored each entire URL. PostgreSQL
reported `index row size 4568 exceeds btree version 4 maximum 2704`.
The transaction rolled back; its descendants correctly became `skipped`.
Repeating Discover before applying the correction encounters the same problem.

The replacement unique expression index uses `(domain_id, SHA-256(URL))`.
The original `urls.url` TEXT column, IDs and dependent records remain unchanged.
No truncation, filtering of long URLs, data reset or database extension is needed.
Katana's ON CONFLICT target uses the same expression as the index.
SHA-256 has the usual theoretical collision limitation of digest-based identity.

Migration `bc64c6f0e217` builds the replacement index before dropping the old
constraint in one PostgreSQL transaction. If it cannot acquire a lock or build
the index, PostgreSQL rolls the transaction back. Lock timeout is five seconds;
statement timeout is 120 seconds. Downgrade attempts to rebuild the old constraint
first and fails transactionally if stored long URLs no longer fit. Do not
truncate or delete those URLs to make a downgrade succeed.

The digest expression doubles literal backslashes before casting text to bytea,
so sequences such as `\xAB` and `\123` retain their exact bytes. It uses only
PostgreSQL core immutable functions. `convert_to()` and `textsend()` are stable
functions and cannot directly be used in an expression index. SQLite unit tests
register a deterministic SHA-256 function; PostgreSQL integration validates the
actual database behavior and Alembic's reflection of the resulting index.

## Reviewed Neptun update

The operator command `scripts/update-url-index.py` is read-only unless `--apply`
is supplied. It requires the full reviewed target commit to already be merged
into `sprint-1.0.2-feature-architecture`. The starting server commit must be
`e51860b931bec53c8b7ba9375c101678374d40af`, or that exact target on repeat runs.

The command checks the deployment branch, local edits, runtime bind mounts,
single worker and scanner processes, active jobs, database revision and URL
index. The application's database name, server address, port and version must
match the existing PostgreSQL 16 container used for the backup. Updater 1.0.1
normalizes PostgreSQL's host-mask notation (`172.18.0.6/32` or IPv6 `/128`)
before comparing the exact host address with Docker. A shared subnet never
allows a different server address. Actual mismatches report the compared
non-secret fields. It refuses active or queued jobs, unexpected edits, untracked
source collisions and changes outside the reviewed backend correction.

On apply it closes API submissions, checks the queue again, freezes the verified
idle worker main process with SIGSTOP, and keeps its container available for
maintenance subprocesses. It saves the private configurations, database row
fingerprints and a custom-format pg_dump in a private directory under `.git`.
The dump's table of contents must be readable before source installation begins.

Then it fast-forwards Git, migrates using the worker's existing Python environment
and connection configuration, and compares every existing table's count and row
fingerprint. It resumes and restarts the worker, starts the API and checks both
API routes, nginx forwarding and one ordinary dummy job. It does not run a real
scan, rebuild the frontend, recreate containers or modify Compose files.

A failed uncommitted migration restores the old application code. A committed
migration keeps the matching new code; it is never automatically downgraded.
If the code/schema combination cannot be confirmed, both API and worker remain
stopped with the backup location printed for inspection. No automatic database
restore or row deletion is performed.

After the command prints `VERIFIED`, start one new Discover run for the same
domain. The failed job 109 and its skipped descendants remain in the history.
The new run should pass Katana and reach URLProbe, HeaderProbe, HeaderFindings,
Screenshot and NucleiURL. Actual reachability and scanner results still depend on
the selected hosts and installed tools.

## Validation

The PostgreSQL 16 integration reproduces the original SQLSTATE 54000 with the
old index, upgrades a populated URL graph, and verifies that every existing row
is identical afterward. It checks URLs above both the 2,704-byte B-tree tuple
limit and 8 KiB, deduplication, distinct suffixes, cross-domain identity, Unicode,
literal backslashes, direct inserts, ORM updates and Katana job completion.
Operator tests cover backup ordering, active-job races, configuration preservation,
failed migrations, coherent rollback, unknown schemas and repeat execution.
