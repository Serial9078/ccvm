# Persistent Nuclei templates

The worker image copies the Nuclei binary, while scans disable automatic
engine/template update checks. A newly created worker previously had no catalog
and failed immediately with `no templates provided for scan`, even though the
earlier discovery and screenshot stages had completed.

The URL plugin now prepares an explicit template directory before launching the
scanner and passes it using `-t`. The default is
`backend/.scanner-data/nuclei-templates` on the host, exposed as
`/app/.scanner-data/nuclei-templates` through the existing backend bind mount.
This data is excluded from Git and Docker build contexts and survives worker container replacement without
changing private Compose configuration. `NUCLEI_TEMPLATES_DIR` can select an
existing custom catalog.

The same directory is passed as `-update-template-dir` to set Nuclei's catalog
root, including references to helper files. The scan's disabled update check
prevents that setting from triggering a template download during execution.

For a missing catalog, the plugin invokes the official `nuclei -update-templates
-update-template-dir DIRECTORY` command with a 120-second deadline. It downloads
into a temporary sibling directory and publishes the catalog only after a
successful exit and a nonempty YAML inventory. A file lock prevents simultaneous
installs. An existing catalog is reused. Empty existing directories are preserved
and rejected rather than overwritten. Scans retain `-disable-update-check`;
that flag is intentionally absent from the template installation command.

Template preparation failure marks the job failed before the scanner launches.
Nonzero scanner exits still fail the job and retain imported partial findings.
The error summary prioritizes fatal/error messages over trailing JSON statistics.
Request rate, concurrency, selected targets, redirect policy and scan timeout are
unchanged.

## Existing Neptun deployment

Use `scripts/update-nuclei-templates.py --target FULL_MERGE_SHA --job ID:UUID`
for read-only preflight and add `--apply` to activate. Supported source states are
`e2a7fc16592e88b54a25313f8b6c57abe14132f9` and the reviewed target. The remote
deployment branch must equal the target. Production job identities belong in the
invocation and private backups only.

The operator requires one failed NucleiURL stage with the diagnosed missing-template
message, all nine earlier stages finished, and no queued/running work. It reuses
the staged maintenance implementation with a separate backup prefix and retry
journal. A private database backup and all-table fingerprints precede source
installation. The existing API is closed and the worker is paused. A helper using
the same worker image mounts application source read-only and only `.scanner-data`
writable. It installs the catalog and confirms that the real Nuclei engine can
list templates using the production tags and severities, without sending any
scan requests.

After unchanged database fingerprints and configuration are verified, the worker
reloads the corrected source. A short transaction locks and rechecks the whole
pipeline and requeues only the selected failed Nuclei job. IDs, UUIDs, earlier
results and dependencies remain intact; no new pipeline is created. Retry intent
is journaled before the write, so repeat invocations only verify after intent.
The database schema is not changed. Failed preparation can restore source only;
no database restore or downgrade occurs. Private cache data is retained.

The final operator output reports whether the selected job is running or finished.
A running job still requires observing its terminal result. Previous HeaderFindings
recovery journals are unaffected.

## Verification

Offline tests cover atomic installation, failure/timeout cleanup, catalog reuse,
explicit paths, meaningful errors, and selected-stage recovery guards. Disposable
PostgreSQL CI executes the actual retry transaction and checks changed-snapshot
refusal. Docker CI uses the production Nuclei v3.11.0 version to install and list
official templates, then proves reuse after container replacement. The complete
URL plugin scans a synthetic HTTP fixture and imports its finding on an internal
Docker network with no external route. Production domains are not contacted by CI.

[Official Nuclei template and CLI documentation](https://github.com/projectdiscovery/nuclei-docs/blob/main/docs/nuclei/get-started.md)
