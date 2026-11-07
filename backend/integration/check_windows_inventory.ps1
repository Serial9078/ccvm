$ErrorActionPreference = 'Stop'
$collector = Join-Path $PSScriptRoot '..\app\services\windows_inventory.ps1'
$tokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile($collector, [ref]$tokens, [ref]$parseErrors) | Out-Null
if ($parseErrors.Count -gt 0) { throw 'PowerShell collector has syntax errors' }
if ((Get-Content -LiteralPath $collector -Raw) -match 'Win32_Product') {
    throw 'Software collection must not invoke the MSI product provider'
}
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
        foreach ($package in $data.packages.items) {
            if ($package.architecture -ne 'unknown' -or
                $package.registry_view -notin @('native', 'wow6432') -or
                $package.install_scope -ne 'machine' -or
                $package.publisher -isnot [string] -or
                $package.registry_key -isnot [string] -or !$package.registry_key) {
                throw 'Registry package identity is missing or claims a binary architecture'
            }
            $base = if ($package.registry_view -eq 'native') {
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
            } else {
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
            }
            $nativePackage = Get-ItemProperty -LiteralPath (Join-Path $base $package.registry_key)
            if ($package.name -ne [string]$nativePackage.DisplayName -or
                $package.version -ne [string]$nativePackage.DisplayVersion -or
                $package.publisher -ne [string]$nativePackage.Publisher) {
                throw 'Registry package identity differs from its recorded key and view'
            }
        }
    }
    Write-Output "Native Windows collector passed: $mode; packages=$($data.packages.items.Count); hotfix coverage=$($data.hotfixes.status)"
}

# Exercise the real collector with synthetic registry responses. No registry
# keys are created, altered or deleted, and no installed product is executed.
foreach ($scenario in @('complete', 'truncated', 'registry-unavailable', 'hotfixes-unavailable')) {
    $fixture = & {
        param($collectorPath, $scenario)
        function Test-Path {
            [CmdletBinding()]
            param([string]$LiteralPath)
            if ($LiteralPath -in @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
            )) { return $true }
            Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath
        }
        function Get-ItemProperty {
            [CmdletBinding()]
            param([string]$LiteralPath, [string]$Path)
            if ($LiteralPath) {
                return Microsoft.PowerShell.Management\Get-ItemProperty -LiteralPath $LiteralPath
            }
            if ($Path -eq 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') {
                $count = if ($scenario -eq 'truncated') { 10001 } else { 1 }
                foreach ($index in 1..$count) {
                    [pscustomobject]@{
                        DisplayName='Fixture Native Software'; DisplayVersion='1.2.3'
                        Publisher='Fixture Publisher'; PSChildName="fixture-native-$index"
                    }
                }
                return
            }
            if ($Path -eq 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
                if ($scenario -eq 'registry-unavailable') { throw 'Synthetic access denied' }
                if ($scenario -ne 'truncated') {
                    [pscustomobject]@{
                        DisplayName='Fixture WOW Software'; DisplayVersion='4.5.6'
                        PSChildName='fixture-wow'
                    }
                }
                return
            }
            throw 'Collector attempted an unexpected registry read'
        }
        function Get-HotFix {
            [CmdletBinding()]
            param()
            if ($scenario -eq 'hotfixes-unavailable') { throw 'Synthetic unavailable hotfix source' }
            [pscustomobject]@{HotFixID='KB1234567'; Description='Fixture update'}
        }
        $ccvmMode = 'inventory'
        & $collectorPath | ConvertFrom-Json
    } $collector $scenario

    if ($scenario -eq 'registry-unavailable') {
        if ($fixture.packages.status -ne 'unavailable' -or $fixture.packages.items.Count -ne 0 -or
            $fixture.hotfixes.status -ne 'complete' -or $fixture.hotfixes.items.Count -ne 1 -or
            !$fixture.os.kernel) {
            throw 'Registry failure changed independently collected OS or hotfix evidence'
        }
    } elseif ($scenario -eq 'truncated') {
        if ($fixture.packages.status -ne 'truncated' -or $fixture.packages.items.Count -ne 10000 -or
            $fixture.packages.items[-1].registry_key -ne 'fixture-native-10000' -or
            $fixture.packages.items[-1].publisher -ne 'Fixture Publisher') {
            throw 'Truncated registry collector lost its cap or package identity'
        }
    } else {
        if ($fixture.packages.status -ne 'complete' -or $fixture.packages.items.Count -ne 2) {
            throw 'Synthetic registry collector returned unexpected coverage'
        }
        $native = $fixture.packages.items[0]
        $wow = $fixture.packages.items[1]
        if ($native.registry_view -ne 'native' -or $native.registry_key -ne 'fixture-native-1' -or
            $native.publisher -ne 'Fixture Publisher' -or $native.install_scope -ne 'machine' -or
            $native.architecture -ne 'unknown' -or
            $wow.registry_view -ne 'wow6432' -or $wow.registry_key -ne 'fixture-wow' -or
            $wow.publisher -ne '' -or $wow.install_scope -ne 'machine' -or
            $wow.architecture -ne 'unknown') {
            throw 'Synthetic registry identity differs or invents architecture/publisher evidence'
        }
        if ($scenario -eq 'hotfixes-unavailable' -and
            ($fixture.hotfixes.status -ne 'unavailable' -or $fixture.hotfixes.items.Count -ne 0)) {
            throw 'Hotfix collection failure is not represented independently'
        }
    }
    Write-Output "Synthetic registry collector passed: $scenario"
}
