# Windows inventory with remote shells prohibited

`AllowRemoteShellAccess=false` is compatible with a separate, directly queried
WMI provider on a Windows WS-Management endpoint. CCVM's existing WinRM inventory
uses a WinRS shell and cannot use that provider yet. Keep the shell restriction
in place. This probe establishes remote read access before implementing a new
inventory provider; it does not enable that provider in the application.

## What the probe does

Run `scripts/probe-windows-cim.py` from `/opt/ccvm` on Neptun after `sudo -v`, with
the customer's numeric ID and one literal target IP. It reads the credential
selected by the most recent saved host audit for exactly that customer and IP.
A missing, non-WinRM, revoked, out-of-scope, or undecryptable credential stops the probe.
It does not guess another username, account, domain, or password.

The probe uses the worker's existing mandatory encrypted HTTP/NTLM session to
query `root/cimv2/Win32_OperatingSystem` on port 5985. It requests one instance,
allows at most one continuation, and releases unfinished enumeration contexts.
It never opens a remote shell, runs a remote command, changes a service, or
changes the application, database, jobs, credentials, or firewall rules. Raw
transport exceptions and SOAP responses are not printed.

A successful result contains only host name, OS caption, version, base build,
architecture, product type, and OS SKU. A failed result contains a fixed phase,
a safe error category, and bounded numeric WSMan/WMI error codes where available.

## Interpreting the result

- Local WMI success does not prove that the saved scanner credential has remote
  WMI permission. This probe tests that separate path from the CCVM worker.
- Success establishes OS read access, not installed-software or patch coverage.
- `BuildNumber` without the update revision is not a complete Windows build.
- Windows client patch assessment currently requires explicit Windows Update
  Agent offer evidence. CIM OS evidence must not produce a patched/green result.
- Fixed registry reads would be a separate, explicitly limited extension. They
  require provider method permission; do not grant broad WMI method access just
  to make this OS-only probe pass.
- If management reads are also prohibited, use an approved outbound collector
  or a read-only management-system connector instead of changing the policy.

## References

- [Microsoft: obtaining WMI data through WS-Management](https://learn.microsoft.com/en-us/windows/win32/winrm/obtaining-data-from-a-remote-computer)
- [Microsoft: Get-WSManInstance](https://learn.microsoft.com/en-us/powershell/module/microsoft.wsman.management/get-wsmaninstance)
- [Microsoft: RemoteShell policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-remoteshell)
