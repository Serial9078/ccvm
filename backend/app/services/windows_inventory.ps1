$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
$current = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
$nativeArchitecture = if ($env:PROCESSOR_ARCHITEW6432) {
    [string]$env:PROCESSOR_ARCHITEW6432
} else {
    [string]$env:PROCESSOR_ARCHITECTURE
}
$software = @{status='not_requested'; source='registry-uninstall'; items=@()}
$hotfixes = @{status='not_requested'; source='Get-HotFix'; items=@()}
if ($ccvmMode -eq 'inventory') {
    try {
        $paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $rows = @()
        foreach ($path in $paths) {
            # An absent 32-bit hive is normal. Access denied is not success.
            $parent = $path.Substring(0, $path.Length - 2)
            if (Test-Path -LiteralPath $parent -ErrorAction Stop) {
                $rows += @(Get-ItemProperty -Path $path -ErrorAction Stop |
                    Where-Object { $_.DisplayName } |
                    Select-Object @{N='name';E={[string]$_.DisplayName}},
                                  @{N='version';E={[string]$_.DisplayVersion}},
                                  @{N='architecture';E={'unknown'}})
            }
        }
        $software = @{status=$(if ($rows.Count -gt 10000) {'truncated'} else {'complete'});
                      source='registry-uninstall'; items=@($rows | Select-Object -First 10000)}
    } catch {
        $software = @{status='unavailable'; source='registry-uninstall'; items=@()}
    }
    try {
        $rows = @(Get-HotFix -ErrorAction Stop |
            Select-Object @{N='id';E={[string]$_.HotFixID}}, @{N='description';E={[string]$_.Description}})
        $hotfixes = @{status=$(if ($rows.Count -gt 10000) {'truncated'} else {'complete'});
                     source='Get-HotFix'; items=@($rows | Select-Object -First 10000)}
    } catch {
        $hotfixes = @{status='unavailable'; source='Get-HotFix'; items=@()}
    }
}
@{
    schema_version=1
    os=@{family='Windows'; name=[string]$os.Caption; version=[string]$os.Version;
         kernel=([string]$os.BuildNumber + '.' + [string]$current.UBR);
         architecture=[string]$os.OSArchitecture; hostname=[string]$os.CSName;
         product_type=[string]$os.ProductType; sku=[string]$os.OperatingSystemSKU;
         installation_type=[string]$current.InstallationType;
         edition_id=[string]$current.EditionID; display_version=[string]$current.DisplayVersion;
         native_architecture=$nativeArchitecture}
    packages=$software
    hotfixes=$hotfixes
} | ConvertTo-Json -Depth 6 -Compress
