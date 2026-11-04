# Authenticated host inventory

This milestone adds a separate operator-only workflow at `/host-audits`. It
collects operating-system and installed-software evidence from one explicitly
selected IP address. It does not yet calculate missing patches, correlate CVEs,
run arbitrary commands, scan an entire subnet with credentials, or establish
Tenable feature parity. The existing TCP discovery/audit pipeline is unchanged.

## Evidence and limits

| Transport | Identity verification | Collected evidence | Requirements and limits |
| --- | --- | --- | --- |
| SSH password or encrypted private key | Explicit, independently approved `SHA256:` host-key fingerprint, checked before authentication | Linux OS release, kernel, architecture, hostname; installed dpkg or RPM package names, versions and architectures | Python 3 on target; no SSH agent, key search, sudo or installation. Other package managers are unavailable. |
| WinRM NTLM over HTTPS | CA and IP subject alternative name validation; TLS checks cannot be disabled; channel binding enabled | Windows OS version and build/UBR; machine-wide 32/64-bit uninstall-registry entries; `Get-HotFix` | Default port 5986; target certificate must cover the literal IP. Dedicated account needs remote execution plus read access to these sources. No Basic/HTTP, CredSSP or delegated credentials. |

`Get-HotFix` is not a complete Windows update inventory. The uninstall registry
does not cover every application, per-user installations or every package type.
Linux packages are local database evidence, not proof of vulnerability or of a
vendor security fix. `Win32_Product` is deliberately not used because querying
it can trigger MSI consistency checks and repair operations.

Each section has an explicit coverage status. Unavailable, malformed, oversized
or truncated evidence does not become a successful audit. Valid partial evidence
is retained when a section is incomplete. A connection test authenticates and
reads OS identity without enumerating packages or hotfixes. No findings are
created or closed by this inventory milestone.

## Access and secret handling

The legacy application has no application-wide authentication/RBAC. New
credential CRUD, inventory metadata, evidence and cancellation endpoints all
require both HTTPS and a separate operator bearer token. That token has operator
access across customers; it is not a customer login or a replacement for broader
API authentication. Existing endpoints retain their existing access model.

Configure the following locally; keep values out of Git, chat and command lines:

| Setting | Containers | Purpose |
| --- | --- | --- |
| `CCVM_AUDIT_VAULT_KEY` | Backend and worker | Base64-encoded random 32-byte AES-256-GCM key, stable across restarts |
| `CCVM_AUDIT_OPERATOR_TOKEN` | Backend only | Independent random bearer token, at least 32 characters |
| `CCVM_NETWORK_ALLOWED_CIDRS` | Backend and worker | Existing mandatory scanner allowlist |
| `CCVM_WINRM_CA_BUNDLE` | Worker, optional | Path to an operator-mounted read-only PEM CA bundle; absent means the runtime's normal trusted CAs |

`python3 scripts/init-audit-secrets.py --directory /an/existing/private/parent/audit`
creates a new 0700 directory with separate 0600 `vault.env` and `operator.env`
files, without displaying their values. Existing files, partial initialization
and symlinks are refused rather than overwritten. Supply `vault.env` to backend
and worker and `operator.env` to backend using private Compose `env_file` entries
or the deployment's secret provider. The helper does not deploy or alter Compose.

Back up the vault key separately from the database. Losing or replacing it makes
existing credentials unreadable. Key rotation/re-encryption is not implemented;
do not generate replacement files over an existing deployment. Operator-token
rotation is independent. Revoking a credential erases its stored ciphertext,
blocks new use and cancels queued/running uses when checked by the worker. Prior
database backups may still contain encrypted copies and must follow the normal
backup retention policy.

Credential ciphertext authenticates customer, UUID, account, kind and CIDR scope
as associated data. Random 96-bit nonces are generated per encryption. API output
never contains the secret or ciphertext. Validation responses omit input and
error context, and private endpoints return `Cache-Control: no-store`. The UI
keeps the operator token only in the mounted page's memory and clears it on lock,
navigation or reload. It never uses browser storage or query/mutation caches for
tokens, credentials or inventory. A private key is read from a local file so its
line breaks survive browser input handling.

Every run freezes the customer/IP asset, credential identity/ciphertext, address,
port, mode and approved SSH fingerprint. Backend and worker both enforce the
scanner allowlist and the credential's narrower CIDR list. Generic `/jobs`
creation cannot enqueue a usable authenticated scan. Changing scope or identity
invalidates the frozen request. Only one run per customer/address may be active.

## Rollout contract

This source change does **not** automatically activate the feature or log into
production hosts. A reviewed deployment must:

1. Retain private Compose overrides, nginx configuration, scanner/template data,
   screenshots, evidence and local modifications. Wait for an idle worker and
   take a private database/configuration backup before migration.
2. Build Python dependencies in the backend and worker **before** starting new
   source. On an existing customized scanner, extend the exact deployed worker
   image and preserve scanner binary hashes; rebuilding floating scanner stages
   is not an equivalent deployment. Keep the existing network override and all
   its mounts and scope settings.
3. Apply the additive migration to `a4c1d8e7f209` in maintenance mode. It creates
   empty credential/inventory tables and does not queue scans or change existing
   observations/findings. Downgrade refuses to discard any credential/history.
4. Serve the UI and API through a trusted HTTPS origin. Configure Uvicorn to trust
   forwarded protocol headers only from the actual trusted reverse proxy, block
   direct API access from untrusted clients, and overwrite forwarded headers at
   ingress. Do not use a wildcard proxy trust setting on a publicly reachable
   backend. A client-supplied `X-Forwarded-Proto` is not accepted by the application
   as proof of HTTPS. The new UI also rejects cross-origin API bases.
5. Provision the two private environment settings and, if needed, the WinRM CA
   bundle. Verify dependency imports, schema, old scanner binary identities,
   `/health`, old pipeline status and the HTTPS proxy before allowing new jobs.
6. Open **Authenticated inventory**, choose a customer, unlock with the local
   operator token, add a dedicated scoped inventory account, independently
   verify the SSH fingerprint or Windows TLS certificate, and test one host.
   Only then collect a full inventory. Never paste passwords/private keys into
   chat. Successful connection-only evidence is not full package/patch coverage.

The transport runs in a separate process. Secrets travel through stdin, not
arguments or files; no DB credentials, vault key, operator token, SSH agent,
proxy or netrc settings are inherited. Local hard deadlines are 45 seconds for a
connection test and 180 seconds for inventory, with process-group termination
and reaping on timeout/cancellation. Remote execution uses fixed read-only
collectors, with temporary package-output storage on Linux; no target settings
or packages are changed. Killing a client cannot guarantee instant cleanup of a
remote WinRM shell; normal server idle limits still apply.

Limits: 10,000 rows per section, 500 characters per text field, 8 MiB transport
output, a 512 MiB transport address-space limit and a 3 MiB Linux package-command
output limit. Unsupported/denied sources are explicitly unavailable. A machine
with large inventory can require a later paginated collector rather than a
misleading complete result.

## Protocol coverage view

The network service dialog now groups open endpoints by port/service/TLS tunnel.
It separates completed evidence, host-level references, unavailable results,
services with no applicable current rule, pending audits and work that was not
run. It derives rule applicability on the backend. An empty result for an SSH
service is unavailable/pending, not "no rule". Counts are endpoints, not CVEs or
successful security checks. This exposes the actual service types needing rule
expansion without guessing from their port numbers.

## Verification

### Existing Docker/HAProxy deployment

`scripts/deploy-authenticated-inventory.py` provides the reviewed rollout for the
retained legacy base. Run it from the deployment checkout using the full reviewed
merge SHA, host name, HTTPS DNS name, browser/VPN CIDRs, existing certificate
basename and four independently confirmed immutable image IDs. Operational
values remain local. Its default is a read-only service preflight; `--apply`
activates it and `--resume` reconciles its own private retained journal.

The operator requires Compose 2.24.4 or newer, the existing network override, an
idle worker and a master-worker HAProxy SNI router without chroot. It builds on
the exact deployed Python/scanner images, checks all seven scanner executable
hashes, builds the frontend and validates the proposed HAProxy configuration
before maintenance. It then stops API submissions and the idle worker, takes a
private PostgreSQL custom dump and proves that migration preserves every old
row. An interruption before migration restores the original application
containers. After migration it retains the additive schema, closes application
writers on failure and resumes from the journal; it never downgrades data.

The additional private Compose overlay binds the legacy API/UI ports to
localhost. HAProxy keeps its existing container and unrelated routes. Only the
selected SNI hostname reaches an internal TLS frontend, where the original
client address is checked against the browser/VPN allowlist. A protected Unix
socket carries PROXY protocol to a dedicated nginx gateway; this gateway has no
published TCP port. Both ingress layers overwrite forwarded headers. Uvicorn
trusts only the gateway's reserved application-network address. The scanner
allowlist is preserved independently of the browser/VPN networks.

Verification exercises real TLS certificate validation, the public SNI path,
allowed/denied client addresses, forged forwarded headers and missing/wrong/valid
operator tokens. A verified repeat only verifies; it does not stop work,
regenerate keys or enqueue jobs. The operator prints private recovery and token
**file paths**, never token/key values. Read the token locally for the UI and
back up the vault key separately. Configure internal DNS for the chosen name to
reach this edge; deployment probes do not prove client DNS or VPN routing.

CI deploys this same operator into a disposable Docker stack with PostgreSQL 16,
HAProxy 3.1, nginx and a private test CA. It verifies the preserved unrelated TLS
application, real socket permissions, loopback port replacement, a retained
private env-file, post-migration recovery and idempotency. Nmap is real in this
fixture; the other scanner executables are inert hash-preservation fixtures.
Existing scanner integration jobs continue to exercise their actual runtimes.

Backend tests cover access boundaries, customer/CIDR scoping, ciphertext/AAD
tampering, secret redaction, frozen requests, revocation, partial evidence,
cancellation and process deadlines. A native loopback SSH fixture exercises a
real handshake, pin rejection before authentication, passwords, encrypted private
keys and the real Linux package collector. PostgreSQL CI checks bytea/JSON
round-trips, preservation of existing rows and destructive downgrade refusal.
Windows CI executes the fixed collector on a native Windows runner. The WinRM
transport contract is tested, but an end-to-end login against a deployed Windows
WinRM listener still requires the operator's trusted certificate and account.
Browser fixtures exercise HTTPS, volatile credentials, connection/inventory
requests, evidence, revocation and locking without any real scan or login.

Primary references:

- [Paramiko client and host-key policy](https://docs.paramiko.org/en/stable/api/client.html)
- [pywinrm transport and authentication](https://github.com/diyan/pywinrm)
- [cryptography AES-GCM API](https://cryptography.io/en/stable/hazmat/primitives/aead/)
- [Microsoft Get-HotFix coverage](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix?view=powershell-5.1)
- [Microsoft MSI consistency-check behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-server/admin-development/windows-installer-reconfigured-all-applications)
