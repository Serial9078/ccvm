# Windows CIM base inventory

Windows clients and servers can expose WMI management data through WS-Management
while `AllowRemoteShellAccess=false` remains enforced. CCVM offers a separate CIM
base inventory for this configuration. It never falls back to a remote shell.

## Select an explicit collection method

For Windows, select **CIM-Basisinventur** in the inventory dialog. The separate
transport selection still controls validated HTTPS or mandatory encrypted
HTTP/NTLM messages. Existing saved runs keep their original method and transport;
retrying a run does not silently change either.

- `cim_connection` reads one OS identity through the WMI provider.
- `cim_inventory` records OS identity and available `Win32_QuickFixEngineering`
  hotfix entries. It intentionally does not request installed-software data.
- Existing `connection`, `inventory`, and `windows_updates` modes use the
  existing WinRS implementation on Windows. They require an allowed remote shell.
  Offered-update searches remain a separate explicit operation.

The mode is stored in the existing audit record and included in its frozen scope
hash. No credential kind, encryption identity, or database schema changes are
needed. The CIM provider records `collection_method="cim"` in its evidence.

## What the results establish

A successful CIM run identifies the actual Windows client/server product type,
host name, OS version, base build, architecture string and SKU. Recorded QFE
entries show what that WMI class reported at collection time. They do not provide
an exhaustive update inventory or establish that missing updates are installed.

CIM base inventory does not read uninstall registry keys, perform Windows Update
Agent searches, or collect the registry build revision (UBR). A base build such
as `10.0.26300` must never be completed by inventing a revision of zero. Installed
software and patch coverage remain unassessed; zero software rows are not a
successful software assessment.

The overview retains CIM identity and labels its limited coverage. An older
WinRS assessment cannot apply to a newer CIM snapshot. Patch and software
assessment endpoints reject CIM base inventories, even if a catalog is present.
An unavailable QFE query retains independently collected OS identity and reports
the unavailable section. A bounded/truncated QFE enumeration is not complete.

## Security and deployment

Only fixed OS and QFE Enumerate/Pull/Release resources are supported. There
are no caller-supplied WQL queries, resource URIs, provider methods or commands.
The collector does not use `Win32_Product`, remote process creation, PowerShell,
registry methods, or policy changes. Existing customer/CIDR scope, revocation,
cancellation, endpoint restrictions, NTLM encryption and isolated-process limits
apply to both methods.

The update publishes the reviewed backend and frontend onto the retained
deployment. It preserves application data, credentials, accounts, MFA settings,
sessions and ingress. It does not retry a failed job or start a scan. After
installation, explicitly start a CIM base inventory for the desired host.

## Evidence and references

The read-only readiness probe successfully read the Windows 11 Pro identity from
the CCVM worker using the saved credential while remote shells remained blocked.
That pilot established remote OS read access, not QFE availability or patch
coverage on every system.

- [Microsoft: WMI data through WS-Management](https://learn.microsoft.com/en-us/windows/win32/winrm/obtaining-data-from-a-remote-computer)
- [Microsoft: Win32_QuickFixEngineering](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-quickfixengineering)
- [Microsoft: RemoteShell policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-remoteshell)
