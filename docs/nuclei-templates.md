# Nuclei catalog, policy and execution diagnostics

The URL scanner uses an explicit catalog at
`backend/.scanner-data/nuclei-templates` on Neptun, exposed through the existing
backend bind mount as `/app/.scanner-data/nuclei-templates`. Git and Docker build
contexts exclude this data. `NUCLEI_TEMPLATES_DIR` can select an existing custom
catalog. Both `-t` and `-update-template-dir` select this root, including helper
file references. Scans retain disabled update checks, redirects and Interactsh.

## Template and ignore-policy preparation

The official installer writes `.nuclei-ignore` into Nuclei's configuration
directory, outside its template directory. Persisting only templates therefore
lost the official exclusions when the installation helper exited. The engine
logs this as an error but continues with empty exclusions. Catalog listing alone
was insufficient to prove policy availability.

Preparation now asks the actual binary for its configuration directory through
`nuclei -version`, honoring the engine's configuration environment. A successful
installation bundles the official `.nuclei-ignore` alongside the catalog. Every
scan restores that policy atomically if the current container lacks it. Existing
nonempty user policies and configuration files remain untouched; existing empty
policy files cause a controlled failure instead of being overwritten. The policy
is never replaced by an empty placeholder.

For catalogs provisioned before this correction, when neither a bundled nor a
local policy exists, the official updater runs in a temporary sibling directory
with a 120-second deadline. Only its official policy is copied into the existing
catalog; existing templates are retained byte for byte. Fresh catalog downloads
are published atomically after a successful exit, a nonempty YAML inventory and
a valid nonempty policy. A file lock prevents simultaneous installations.
Template listing rejects missing or unparsable ignore-policy diagnostics even if
the engine exits zero and lists some templates.

## Execution and evidence

The fixed 20-minute cap could interrupt the full catalog across many URLs.
`CCVM_NUCLEI_TIMEOUT_SECONDS` now sets the absolute limit, defaulting to 7,200
seconds. `CCVM_NUCLEI_STALL_SECONDS` defaults to 300 seconds without a change in
reported request or match counters. Missing statistics also trigger this stall
limit. Each limit must be a positive integer. Request rate remains 30 per second,
concurrency remains 5, and URL selection retains the same limits and domain rules.
No URL or template subset is silently removed to report a successful scan.

Nuclei receives both `-no-stdin` and a closed child stdin. Progress uses scanner
statistics, with the current absolute limit visible in the job message. A failed
or interrupted scan remains failed; successfully imported partial findings stay
available. Terminal messages retain the final request counters when available.

Every attempt keeps private diagnostics under
`backend/.scanner-data/nuclei-runs/job-ID-*`: job ID/UUID, target list, stdout,
stderr, raw findings, latest progress and execution summary. Directory permissions
are private, and JSON snapshots are replaced atomically. `CCVM_NUCLEI_LOG_DIR`
can select another persistent writable location. Logs are retained for operator
inspection; storage cleanup is an explicit operational task. Nothing is exposed
through a new public file endpoint.

## Existing Neptun deployment

`scripts/update-nuclei-templates.py` version 1.1.0 supports source commit
`827fec9aed5d784c742b46bf3af7df9c9f739078` and the reviewed target. Use
`--target FULL_MERGE_SHA --job ID:UUID` for read-only preflight, and add `--apply`
to install the correction. The selected NucleiURL job must have the diagnosed
missing-template failure, or the original 1,200-second timeout together with the
missing-ignore error. All nine earlier stages must be finished; other active
work stops the update.

The existing staged updater backs up the database and private configuration,
pauses the worker, and checks all-table row fingerprints. The same-image helper
mounts source read-only and scanner data writable, prepares the catalog/policy,
and proves engine template loading without sending scan requests. The worker
then reloads, and a locked, snapshot-checked transaction requeues only the selected
job. IDs, UUIDs, completed stages and results are preserved. The schema and Compose
configuration are unchanged.

The new `ccvm-nuclei-runtime-retry.json` journal is separate from the earlier
template-install retry journal. Recorded retry intent prevents duplicate
requeues after a lost response. Unknown state leaves the API closed; failed
preparation can restore source only, never restore or downgrade the database.
A final running status proves startup; terminal scan completion still needs to
be observed.

## Validation

Offline tests cover legacy catalog repair, policy restoration in replacement
containers, preserving custom policies, refusing absent policies, and meaningful
error messages. Execution tests cover progress beyond 20 minutes, the absolute
cap, stalled counters, missing telemetry, partial findings and retained evidence.
Disposable PostgreSQL tests execute the selected retry transaction. Docker CI
uses Nuclei v3.11.0 to install/list official templates, proves catalog and policy
reuse after container replacement, and runs the complete plugin against an
isolated synthetic HTTP fixture. That test checks the real scanner stderr and
retained execution diagnostics, with no external route from the scan network.

References:
[official CLI documentation](https://github.com/projectdiscovery/nuclei-docs/blob/main/docs/nuclei/get-started.md),
[official ignore reader](https://github.com/projectdiscovery/nuclei/blob/v3.11.0/pkg/catalog/config/ignorefile.go),
[official installer](https://github.com/projectdiscovery/nuclei/blob/v3.11.0/pkg/installer/template.go).
