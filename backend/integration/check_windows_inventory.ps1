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
