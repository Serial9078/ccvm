# Network scanning

CCVM now has a separate two-stage network pipeline: `networkdiscovery` uses
Nmap TCP connect scanning and service detection; `networkaudit` checks observed
SSH, TLS, SMB and RDP configuration using a fixed NSE script list. The existing
domain/URL pipeline remains a separate workflow.

## Operator setup

The scanner must have routing to the intended customer networks. Running on
Neptun does not give it access to networks behind unrelated customer VPNs;
deploying distributed workers/sensors is a later capability.

Configure `CCVM_NETWORK_ALLOWED_CIDRS` on **both backend and worker**, for example
`192.168.50.0/24,192.168.65.0/24`. An empty value disables creation of network
scans. This is an operator policy boundary, independently rechecked by the
worker immediately before execution. It does not replace administrator access
control on the existing CCVM API/proxy. No credential storage or RBAC system is
introduced by this feature.

The worker needs the `nmap` executable and its packaged NSE scripts/libraries.
Fresh worker images install the Debian package. For Neptun's existing
worker, extend its reviewed image with `backend/Dockerfile.network-tools` and
an explicit `CCVM_WORKER_BASE` build argument. This retains the existing
Subfinder/DNSX/HTTPX/Naabu/Katana/Nuclei tools instead of replacing their custom
image with a rebuild that also refreshes the existing `latest` ProjectDiscovery
stages. The extension requires a
Debian-based image and a root build; scanning itself uses `--unprivileged -sT`
and does not require host networking, a Docker socket, privileged mode or raw
packet capabilities. Existing private Compose overrides require a reviewed
deployment integration; this branch does not change or activate them.

Before activating new code on an existing database, migrate to revision
`f93b70a4e628`. It adds network run/observation tables and structured port
inventory fields, backfilling existing port state as `open`. Downgrade refuses
to discard network run or structured service evidence. PostgreSQL checks and
table locks protect this refusal against concurrent inserts.

## Using it

Open **Network scans**, select a customer and enter a literal IP or CIDR. Fast,
standard, full and custom profiles cover the top 100, top 1,000, all 65,535 or
explicit TCP ports respectively. Exclude addresses/CIDRs as needed. The optional
scope preview shows canonical targets, the effective address count and a lower
bound for the portscan; it does not send probes. Service probing and audits
add time to that bound. The portscan rate is 10–1,000 probes/second; each stage
has a configurable 60-second to 24-hour budget, defaulting to eight hours. NSE
work has separate script and per-host timeouts; the portscan rate is not a
global NSE request-rate guarantee.

IPv4 and global/ULA IPv6 are supported, with at most 4,096 effective targets.
IPv6 link-local scope identifiers, hostnames, multicast and unspecified targets
are rejected. IPv4 CIDRs omit network/broadcast addresses except /31 and /32;
IPv6 follows host-address semantics. Exclusions are applied with interval math
before bounded expansion, so a huge IPv6 range cannot exhaust worker memory.
Literal target files and disabled reverse DNS keep scope independent of DNS.

Starting a scan stores an immutable, hashed configuration and explicit target
list. Later edits to an asset do not redirect queued work. Customer/network
duplicates with queued or running jobs are rejected. A completed discovery job
is required before its audit job can be claimed. Generic job creation cannot
create these scoped handlers directly.

Nmap runs with `-Pn` to include hosts that do not answer discovery pings. Its
`up/user-set` label therefore is not treated as proof of liveness. Only observed
open services create positive host inventory. Existing observations are not
declared dead merely because a later run gets no response. Ports retain explicit
closed/filtered states; ambiguous omitted states become `not_observed` rather
than staying falsely open. Full products, versions, CPEs and per-run service
evidence remain available independently of the short legacy banner field.

The UI displays both stages, counts, service fingerprints and applicable check
availability, and supports cancellation. The worker polls the cancellation
request and reaps its process; queued children are cancelled without probing.
Missing/failed checks, host timeouts, incomplete XML, missing targets and nonzero
scanner exits produce an incomplete/failed job. Positive partial evidence is
retained. A clean zero-finding audit is distinct from missing evidence.

## Checks and limits

| Check | Evidence required |
| --- | --- |
| Legacy SSH key exchange | Named SHA-1 KEX algorithm advertised by `ssh2-enum-algos` |
| Weak SSH encryption | RC4/DES-family cipher advertised by `ssh2-enum-algos` |
| Legacy TLS/SSL | Successful cipher enumeration for SSL or TLS 1.0/1.1 |
| SMBv1 | The SMBv1 dialect appears in the accepted dialect list |
| Optional SMB signing | Negotiation explicitly reports signing optional/disabled |
| RDP without NLA | Native RDP or SSL security-layer negotiation succeeds |

These are protocol/configuration findings, with raw evidence, severity and
remediation. A service banner or CPE is inventory evidence and never becomes a
guessed CVE. Findings are attributed to the individual customer's IP asset and
deduplicated across scans. A repeated positive observation reopens an existing
fixed finding. Missing NSE output does not automatically close earlier findings.

SMB protocol/signing NSE results are host-scoped. When both TCP 139 and 445 are
open, Nmap selects 445; otherwise it uses 139. CCVM evaluates those results once
on that selected transport and displays a host-level reference on the companion
service. A missing result on the selected transport still fails coverage; the
reference never counts as a separate successful enumeration.

`scripts/correct-network-audit.py` installs the reviewed correction and can
re-evaluate one diagnosed failed audit from retained evidence. It requires a
successful original process exit, the exact frozen command/targets/port scope,
complete XML, unchanged service evidence, and only duplicate SMB-139 coverage
errors. It changes the selected audit status/check references while preserving
findings, discovery results and scan counters. It performs no network probes,
creates no pipeline, and refuses to declare an audit complete while a real
required enumeration remains unavailable. Customer/scope arguments remain local.

This foundation is not Tenable feature parity. UDP/SNMP discovery, authenticated
SSH/WinRM/SNMPv3 inventories, vendor advisory/OVAL feeds, installed-patch checks,
credential management, distributed sensors and scheduled reassessment remain
separate development work. They should build on these explicit scopes and
evidence-backed host/service identities.

## API and retained diagnostics

`GET /api/v1/network-scans/capabilities` reports the configured scanner ranges.
`POST /api/v1/network-scans/preview` validates/counts a scope. `POST /api/v1/network-scans`
queues both jobs atomically, and `GET /api/v1/network-scans/{id}` includes observed
services. `POST /api/v1/network-scans/{id}/cancel` requests cancellation. List
responses can filter by `customer_id`; existing pipelines also include network
asset identity for display.

Every attempt retains its exact command, literal targets, stdout/stderr, Nmap
XML and execution status in private `backend/.scanner-data/network-runs` (or
`CCVM_NETWORK_LOG_DIR`). There is no public filesystem download endpoint. Logs
are retained for investigation; retention/cleanup is an explicit operator task.

Offline tests cover scope/exclusion boundaries, limits, injection rejection,
customer attribution, duplicates, cancellation, incomplete results, positive
protocol rules and process cleanup. PostgreSQL verifies additive migration/data
preservation, native JSON, full service versions and deduplication, plus refusal
of destructive downgrade. Docker CI extends the same worker image, scans a
synthetic SSH service, imports a real NSE finding and proves an excluded canary
gets no connections, on an internal Docker network with no external route.

Primary references: [Nmap service detection](https://nmap.org/book/man-version-detection.html),
[SSH algorithms](https://nmap.org/nsedoc/scripts/ssh2-enum-algos.html),
[TLS enumeration](https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html),
[SMB signing](https://nmap.org/nsedoc/scripts/smb2-security-mode.html).

## First Neptun activation

`scripts/deploy-network-scans.py` requires the confirmed source, immutable
worker/backend image IDs, customer ID/UUID/name and CIDR as local arguments.
Operational customer identities, network ranges and image IDs are never embedded
in the repository; test fixtures use reserved documentation addresses.
It requires an exact reviewed merge SHA on the deployment branch. Without
`--apply` it reads preconditions only. With `--apply` it builds the Nmap worker
extension and frontend before downtime, verifies byte-identical legacy scanner
binaries, saves private configuration/container metadata, and inspects a
PostgreSQL custom-format backup before migration. An idle worker is paused for
the migration; the old row fingerprints exclude only the five additive port
columns, whose empty/default values are checked separately.

It refuses drift between the active containers and the Compose source, and
adds only `docker-compose.network.yml`, leaving existing private files intact.
Only backend/worker are recreated; their existing mounts, environment, networks
and ports must remain the same except for the explicit image/policy changes.
The existing nginx directory bind remains mounted: new hashed assets are copied
first and index.html is replaced atomically. Previous client assets are retained.
The API and frontend proxy must expose the exact selected policy before a scan
can be submitted.

The first scan covers the selected bounded IPv4 scope, the top 100 TCP ports, 100 portscan probes
per second and an eight-hour budget per stage. A private intent journal is
written before submission; a lost response is reconciled against the existing
run rather than blindly submitting it again. A repeated successful invocation
reports the same run even after it has completed. An interrupted activation
after source mutation leaves the backend stopped and worker paused for inspection;
it does not silently downgrade evidence or continue with an unknown runtime.

Future manual Compose operations must include the persistent override:

```bash
sudo docker compose -f docker-compose.yml -f docker-compose.network.yml ps
```

CI additionally rehearses actual Compose recreation on an isolated network,
checks an unrelated container stays unchanged, and verifies publication through
a directory already bind-mounted read-only. No production scan runs in CI.

The 1.0.1 publisher mounts its helper under a CCVM-specific filename and starts
Python in isolated mode from `/tmp`. This avoids shadowing Python's standard
`operator` module when the base image has an empty/root working directory; CI
also exercises a helper image whose working directory is `/`.

For the recorded 1.0.0 publication failure, `--resume-publication --apply`
accepts only the original deployment journal and an operator-only correction.
It verifies the retained build, private Compose configuration, old/current image
identities, customer, schema and database fingerprints. It reuses the migrated
database, extended worker and built frontend; no image rebuild or migration is
performed. After verification it restores the coherent services, publishes the
cached frontend, and submits the first scan through the existing idempotent
journal. A static publishing retry does not stop the verified services again.
