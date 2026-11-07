$ErrorActionPreference = 'Stop'
$collector = Join-Path $PSScriptRoot '..\app\services\windows_inventory.ps1'
$tokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile($collector, [ref]$tokens, [ref]$parseErrors) | Out-Null
if ($parseErrors.Count -gt 0) { throw 'PowerShell collector has syntax errors' }
foreach ($mode in @('connection', 'inventory')) {
    $ccvmMode = $mode
    $json = & $collector
    $data = $json | ConvertFrom-Json
    if ($data.schema_version -ne 1 -or $data.os.family -ne 'Windows' -or !$data.os.kernel) {
        throw 'Native Windows collector did not return OS/build evidence'
    }
    $nativeOs = Get-CimInstance -ClassName Win32_OperatingSystem
    $nativeCurrent = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    if ($data.os.product_type -ne [string]$nativeOs.ProductType -or
        $data.os.sku -ne [string]$nativeOs.OperatingSystemSKU -or
        $data.os.installation_type -ne [string]$nativeCurrent.InstallationType -or
        $data.os.edition_id -ne [string]$nativeCurrent.EditionID -or
        $data.os.native_architecture -notin @('AMD64', 'ARM64', 'x86')) {
        throw 'Native Windows product/installation/architecture identity differs'
    }
    if ($mode -eq 'connection') {
        if ($data.packages.status -ne 'not_requested' -or $data.hotfixes.status -ne 'not_requested') {
            throw 'Connection test unexpectedly enumerated software'
        }
    } else {
        if ($data.packages.status -ne 'complete' -or $data.packages.items.Count -eq 0) {
            throw 'Native Windows software registry inventory is incomplete'
        }
        if ($data.hotfixes.status -notin @('complete', 'unavailable')) {
            throw 'Invalid Get-HotFix coverage state'
        }
    }
    Write-Output "Native Windows collector passed: $mode; packages=$($data.packages.items.Count); hotfix coverage=$($data.hotfixes.status)"
}
