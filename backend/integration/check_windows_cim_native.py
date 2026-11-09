"""Exercise the actual Windows WMI provider with WinRS disabled on a hosted runner.

This fixture changes only its disposable GitHub-hosted Windows runner. It resets
the built-in RID-500 account password, which cannot be restored and is never
printed or written to disk. It accepts no target or credential arguments and must
never be adapted into an operator/deployment command. Service/configuration and
account-enabled states are restored; the runner is destroyed after this job.
"""

import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from time import monotonic

BACKEND = Path(__file__).resolve().parents[1]
ENDPOINT = "http://127.0.0.1:5985/wsman"
SEALED = 'protocol="application/HTTP-SPNEGO-session-encrypted"'
PHASE = "guard"

READ_INPUT = r"""
$ErrorActionPreference = 'Stop'
$stream = [Console]::OpenStandardInput()
$encoding = [Text.UTF8Encoding]::new($false, $true)
$reader = [IO.StreamReader]::new($stream, $encoding, $false, 4096, $true)
try { $rawInput = $reader.ReadToEnd() }
finally { $reader.Dispose() }
if ($rawInput.Length -eq 0 -or $rawInput.Length -gt 65536) {
    throw 'Disposable fixture input is missing or too large'
}
$inputData = $rawInput | ConvertFrom-Json
if ($null -eq $inputData -or $inputData -isnot [pscustomobject]) {
    throw 'Disposable fixture input must be an object'
}
"""

STDIN_PROBE = "$ErrorActionPreference='Stop';try {\n" + READ_INPUT + r"""
if ($inputData.password -isnot [string] -or $inputData.password.Length -lt 32) {
    throw 'Disposable fixture input property is missing'
}
$bytes = [Text.Encoding]::UTF8.GetBytes($rawInput)
$sha = [Security.Cryptography.SHA256]::Create()
try { $digest = [BitConverter]::ToString($sha.ComputeHash($bytes)) }
finally { $sha.Dispose() }
@{bytes=$bytes.Length;sha256=$digest.Replace('-','').ToLowerInvariant()} |
    ConvertTo-Json -Compress
} catch {
    @{status='failed';setup_stage='input';hresult=[int64]$_.Exception.HResult;
      script_line=[int]$_.InvocationInfo.ScriptLineNumber;setting_index=0;
      cleanup_failed=$false} | ConvertTo-Json -Compress
    exit 1
}
"""

RESTORE = r"""
function Restore-CcvmFixture($state) {
    $ok = $true
    foreach ($entry in @($state.Settings)) {
        try { Set-Item -LiteralPath $entry.Path -Value ([bool]$entry.Value) -Force }
        catch { $ok = $false }
    }
    if ($state.CreatedListener) {
        try {
            Remove-WSManInstance -ResourceURI winrm/config/Listener `
                -SelectorSet @{Address='IP:127.0.0.1';Transport='HTTP'}
        } catch { $ok = $false }
    }
    if ($null -ne $state.Listeners) {
        try {
            $fields = @('Address','Transport','Port','Enabled','Hostname',
                        'CertificateThumbprint','URLPrefix')
            $current = @(Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate |
                Select-Object -Property $fields | Sort-Object Address,Transport)
            $before = @($state.Listeners | Sort-Object Address,Transport)
            if (($current | ConvertTo-Json -Depth 4 -Compress) -ne
                ($before | ConvertTo-Json -Depth 4 -Compress)) { $ok = $false }
        } catch { $ok = $false }
    }
    if ($state.AccountSid) {
        try {
            if ($state.AccountEnabled) { Enable-LocalUser -SID $state.AccountSid }
            else { Disable-LocalUser -SID $state.AccountSid }
        } catch { $ok = $false }
    }
    if ($state.ServiceCaptured -and -not $state.ServiceWasRunning) {
        try { Stop-Service -Name WinRM -Force }
        catch { $ok = $false }
    }
    if (-not $ok) { throw 'Disposable fixture cleanup failed' }
}
"""

SETUP = (
    RESTORE
    + r"""
$ErrorActionPreference = 'Stop'
$state = @{Settings=@();CreatedListener=$false;AccountSid=$null;AccountEnabled=$false;
           ServiceCaptured=$false}
$complete = $false
$failure = $null
$cleanupFailed = $false
$stage = 'input'
$settingIndex = 0
try {
"""
    + READ_INPUT
    + r"""
    if ($inputData.password -isnot [string] -or
        $inputData.password.Length -lt 32 -or $inputData.password.Length -gt 128) {
        throw 'Disposable fixture password input is missing or invalid'
    }
    $stage = 'service_state'
    $service = Get-Service -Name WinRM
    $state.ServiceWasRunning = $service.Status -eq 'Running'
    $state.ServiceCaptured = $true
    $stage = 'service_start'
    Start-Service -Name WinRM
    $stage = 'read_settings'
    foreach ($path in @('WSMan:\localhost\Service\Auth\Negotiate',
                         'WSMan:\localhost\Service\Auth\Basic',
                         'WSMan:\localhost\Service\AllowUnencrypted',
                         'WSMan:\localhost\Shell\AllowRemoteShellAccess')) {
        $value = [Convert]::ToBoolean([string](Get-Item -LiteralPath $path).Value)
        $state.Settings += @{Path=$path;Value=$value}
        $settingIndex += 1
    }
    $stage = 'configure_auth'
    Set-Item WSMan:\localhost\Service\Auth\Negotiate -Value $true -Force
    Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false -Force
    Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false -Force
    Set-Item WSMan:\localhost\Shell\AllowRemoteShellAccess -Value $false -Force
    $stage = 'read_listeners'
    $listeners = @(Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate)
    $state.Listeners = @($listeners | Select-Object Address,Transport,Port,Enabled,
        Hostname,CertificateThumbprint,URLPrefix | Sort-Object Address,Transport)
    $usable = @($listeners | Where-Object {
        $_.Transport -eq 'HTTP' -and [int]$_.Port -eq 5985 -and
        [Convert]::ToBoolean([string]$_.Enabled) -and
        $_.Address -in @('*','IP:127.0.0.1')
    })
    if ($usable.Count -eq 0) {
        $stage = 'create_listener'
        New-WSManInstance -ResourceURI winrm/config/Listener `
            -SelectorSet @{Address='IP:127.0.0.1';Transport='HTTP'} `
            -ValueSet @{Enabled=$true;Port=5985} | Out-Null
        $state.CreatedListener = $true
    }
    $stage = 'select_account'
    $account = @(Get-LocalUser | Where-Object {$_.SID.Value -match '-500$'})
    if ($account.Count -ne 1) { throw 'Expected exactly one built-in administrator' }
    $state.AccountSid = $account[0].SID.Value
    $state.AccountEnabled = [bool]$account[0].Enabled
    $stage = 'reset_account'
    $password = ConvertTo-SecureString -String $inputData.password -AsPlainText -Force
    Set-LocalUser -SID $account[0].SID -Password $password
    Enable-LocalUser -SID $account[0].SID
    $stage = 'read_os'
    $native = Get-CimInstance -ClassName Win32_OperatingSystem
    $state.Username = $env:COMPUTERNAME + [char]92 + $account[0].Name
    $state.OS = @{name=[string]$native.Caption;version=[string]$native.Version;
        kernel=[string]$native.BuildNumber;architecture=[string]$native.OSArchitecture;
        hostname=[string]$native.CSName;product_type=[string]$native.ProductType;
        sku=[string]$native.OperatingSystemSKU;family='Windows'}
    $state | ConvertTo-Json -Depth 6 -Compress
    $complete = $true
} catch {
    $failure = @{status='failed';setup_stage=$stage;
        hresult=[int64]$_.Exception.HResult;
        script_line=[int]$_.InvocationInfo.ScriptLineNumber;
        setting_index=$settingIndex}
} finally {
    $inputData = $null; $password = $null
    if (-not $complete) {
        try { Restore-CcvmFixture $state }
        catch { $cleanupFailed = $true }
    }
}
if ($null -ne $failure) {
    $failure.cleanup_failed = $cleanupFailed
    $failure | ConvertTo-Json -Compress
    exit 1
}
"""
)

CHECK = r"""
$ErrorActionPreference = 'Stop'
foreach ($entry in @(
    @{Path='WSMan:\localhost\Service\Auth\Negotiate';Expected=$true},
    @{Path='WSMan:\localhost\Service\Auth\Basic';Expected=$false},
    @{Path='WSMan:\localhost\Service\AllowUnencrypted';Expected=$false},
    @{Path='WSMan:\localhost\Shell\AllowRemoteShellAccess';Expected=$false})) {
    $actual = [Convert]::ToBoolean([string](Get-Item -LiteralPath $entry.Path).Value)
    if ($actual -ne $entry.Expected) {
        throw 'Disposable WinRM security fixture changed'
    }
}
$hotfixes = @(Get-CimInstance -ClassName Win32_QuickFixEngineering | ForEach-Object {
    @{id=[string]$_.HotFixID;description=[string]$_.Description}
})
@{shell_disabled=$true;hotfixes=$hotfixes} | ConvertTo-Json -Depth 4 -Compress
"""


class NativeCheckError(RuntimeError):
    def __init__(self, message, diagnostics=None):
        super().__init__(message)
        self.diagnostics = diagnostics or {}


def setup_diagnostics(output):
    """Extract only fixed setup stages and numeric metadata, never PS errors."""
    try:
        value = json.loads(output.decode("utf-8-sig"))
    except (UnicodeError, ValueError):
        return {}
    fields = {"status", "setup_stage", "hresult", "script_line", "setting_index", "cleanup_failed"}
    stages = {
        "input",
        "service_state",
        "service_start",
        "read_settings",
        "configure_auth",
        "read_listeners",
        "create_listener",
        "select_account",
        "reset_account",
        "read_os",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value.get("status") != "failed"
        or not isinstance(value.get("setup_stage"), str)
        or value.get("setup_stage") not in stages
        or type(value.get("hresult")) is not int
        or not -(2**31) <= value["hresult"] <= 2**32 - 1
        or type(value.get("script_line")) is not int
        or not 0 <= value["script_line"] <= 10000
        or type(value.get("setting_index")) is not int
        or not 0 <= value["setting_index"] <= 4
        or type(value.get("cleanup_failed")) is not bool
    ):
        return {}
    return {key: value[key] for key in fields - {"status"}}


def hosted_windows_only():
    if (
        len(sys.argv) != 1
        or os.name != "nt"
        or sys.platform != "win32"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or os.environ.get("RUNNER_OS") != "Windows"
        or not re.fullmatch(r"[1-9][0-9]{0,19}", os.environ.get("GITHUB_RUN_ID", ""))
        or not re.fullmatch(r"[1-9][0-9]{0,9}", os.environ.get("GITHUB_RUN_ATTEMPT", ""))
    ):
        raise NativeCheckError("Disposable GitHub-hosted Windows runner required")


def powershell(source, payload=None):
    hosted_windows_only()
    executable = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    data = json.dumps(payload or {}).encode("utf-8")
    if len(data) > 65536:
        raise NativeCheckError("Disposable Windows fixture input is too large")
    # The file contains only static fixture code. Credentials and cleanup state
    # are supplied separately over stdin and never written to this file.
    with tempfile.TemporaryDirectory(
        prefix="ccvm-native-ps-", dir=os.environ["RUNNER_TEMP"]
    ) as work:
        script = Path(work) / "fixture.ps1"
        script.write_text(source, encoding="utf-8-sig")
        result = subprocess.run(
            [
                str(executable),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-InputFormat",
                "Text",
                "-OutputFormat",
                "Text",
                "-File",
                str(script),
            ],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=90,
            check=False,
        )
    if len(result.stdout) > 65536:
        raise NativeCheckError("Disposable Windows fixture command failed")
    if result.returncode:
        raise NativeCheckError(
            "Disposable Windows fixture command failed", setup_diagnostics(result.stdout)
        )
    try:
        return json.loads(result.stdout.decode("utf-8-sig"))
    except (UnicodeError, ValueError):
        raise NativeCheckError("Disposable Windows fixture returned invalid metadata") from None


def verify_stdin_channel():
    """Prove the real PS input path before service or account changes are allowed."""
    payload = {"password": "Input9!" + secrets.token_urlsafe(36)}
    expected = json.dumps(payload).encode("utf-8")
    result = powershell(STDIN_PROBE, payload)
    if result != {"bytes": len(expected), "sha256": hashlib.sha256(expected).hexdigest()}:
        raise NativeCheckError("Disposable PowerShell input handshake failed")
    print("PowerShell stdin JSON handshake verified before Windows fixture changes")


def protocol_session(username, password):
    from winrm.protocol import Protocol

    protocol = Protocol(
        endpoint=ENDPOINT,
        username=username,
        password=password,
        transport="ntlm",
        proxy=None,
        message_encryption="always",
        send_cbt=True,
        operation_timeout_sec=15,
        read_timeout_sec=20,
    )
    counts = {"requests": 0, "responses": 0}
    setup = protocol.transport.setup_encryption

    def secured_setup(session):
        session.trust_env, session.proxies = False, {}
        send = session.send

        def sealed_send(request, **kwargs):
            if request.url != ENDPOINT:
                raise NativeCheckError("Unexpected fixture destination")
            protected = bool(request.body)
            if protected:
                if SEALED not in request.headers.get("Content-Type", ""):
                    raise NativeCheckError("Unsealed WSMan request")
                counts["requests"] += 1
            kwargs.update(allow_redirects=False, proxies={})
            response = send(request, **kwargs)
            if response.is_redirect or response.is_permanent_redirect:
                raise NativeCheckError("Unexpected fixture redirect")
            if protected:
                if SEALED not in response.headers.get("Content-Type", ""):
                    raise NativeCheckError("Unsealed WSMan response")
                counts["responses"] += 1
            return response

        session.send = sealed_send
        return setup(session)

    protocol.transport.setup_encryption = secured_setup
    session = protocol.transport.build_session()

    def forbidden(*_args, **_kwargs):
        raise NativeCheckError("A native CIM collection attempted a remote shell")

    for method in (
        "open_shell",
        "run_command",
        "get_command_output",
        "close_shell",
        "cleanup_command",
    ):
        setattr(protocol, method, forbidden)
    original_send = protocol.send_message

    def checked_message(message):
        from app.services import windows_cim

        root = ET.fromstring(message)
        header = root.find("{" + windows_cim.SOAP + "}Header")
        action = header.find("{" + windows_cim.ADDR + "}Action").text
        resource = header.find("{" + windows_cim.WSMAN + "}ResourceURI").text
        destination = header.find("{" + windows_cim.ADDR + "}To").text
        if (
            action
            not in {windows_cim.ENUM + "/" + name for name in ("Enumerate", "Pull", "Release")}
            or resource
            not in {windows_cim.WMI + windows_cim.OS_CLASS, windows_cim.WMI + windows_cim.QFE_CLASS}
            or destination != ENDPOINT
        ):
            raise NativeCheckError("Unexpected native CIM operation")
        return original_send(message)

    protocol.send_message = checked_message
    return protocol, session, counts


def main():
    global PHASE
    hosted_windows_only()
    sys.path.insert(0, str(BACKEND))
    from app.services import windows_cim

    fixture, session, primary = None, None, None
    password = "Ccvm9!" + secrets.token_urlsafe(36)
    try:
        PHASE = "stdin_probe"
        verify_stdin_channel()
        PHASE = "setup"
        fixture = powershell(SETUP, {"password": password})
        PHASE = "security_before"
        before = powershell(CHECK)
        assert before["shell_disabled"] is True
        PHASE = "authenticate"
        protocol, session, counts = protocol_session(fixture["Username"], password)
        for mode in ("cim_connection", "cim_inventory"):
            PHASE = mode
            result = windows_cim.collect(protocol, ENDPOINT, mode, deadline=monotonic() + 120)
            assert result["collection_method"] == "cim"
            assert result["os"] == fixture["OS"]
            assert result["packages"] == {"status": "not_requested", "source": "none", "items": []}
            hotfixes = result["hotfixes"]
            if mode == "cim_connection":
                assert hotfixes["status"] == "not_requested" and not hotfixes["items"]
            else:
                assert hotfixes["status"] == "complete"
                assert hotfixes["source"] == "Win32_QuickFixEngineering"
                PHASE = "security_after"
                after = powershell(CHECK)
                assert after["shell_disabled"] is True
                assert sorted(
                    (item["id"], item["description"]) for item in hotfixes["items"]
                ) == sorted((item["id"], item["description"]) for item in after["hotfixes"])
            print(
                f"Native Windows CIM passed: {mode}; shell disabled; "
                "no software or patch assessment"
            )
        assert counts["requests"] >= 3 and counts["requests"] == counts["responses"]
        print("Real WinRM WMI responses and mandatory NTLM sealing verified")
    except BaseException as error:
        primary = error
        raise
    finally:
        password = None
        cleanup_failed = False
        if session is not None:
            try:
                session.close()
            except Exception:
                cleanup_failed = True
        if fixture is not None:
            try:
                restored = powershell(
                    RESTORE + READ_INPUT + "\nif (-not $inputData.ServiceCaptured -or "
                    "-not $inputData.AccountSid -or @($inputData.Settings).Count -ne 4) "
                    "{throw 'Disposable cleanup input is incomplete'};"
                    "Restore-CcvmFixture $inputData;"
                    "@{restored=$true}|ConvertTo-Json -Compress",
                    fixture,
                )
                if restored != {"restored": True}:
                    cleanup_failed = True
            except Exception:
                cleanup_failed = True
        if cleanup_failed and primary is None:
            raise NativeCheckError("Disposable Windows fixture cleanup failed") from None


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        result = {"status": "failed", "phase": PHASE, "error_type": type(error).__name__}
        if isinstance(error, NativeCheckError):
            result.update(error.diagnostics)
        for field in ("wsman_fault_code", "wmierror_code", "code"):
            value = getattr(error, field, None)
            if type(value) is int and -(2**31) <= value <= 2**32 - 1:
                result[field] = value
        print(json.dumps(result))
        raise SystemExit(1) from None
