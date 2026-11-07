$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
# Search only. No downloader, installer, source registration, policy or service changes.
# A locally started job bounds this client call; WUA service-internal work may outlive it.
$worker = {
    param([bool]$online)
    $ErrorActionPreference = 'Stop'
    function SafeText($value, [int]$limit) {
        $value = ([string]$value) -replace '[\x00-\x1f\x7f-\x9f]', ' '
        if ($value.Length -gt $limit) { return $value.Substring(0, $limit) }
        return $value
    }
    $output = @{
        schema_version=1; source='windows-update-agent'; mode=$(if ($online) {'online'} else {'cached'})
        server_selection='default'; queried_at=[DateTime]::UtcNow.ToString('o')
        status='unavailable'; result_code=$null; total=0; items=@(); truncated=$false
        hidden_updates='not_assessed'; drivers='not_assessed'; superseded='excluded'
        reboot_required=$null; error_code='update_query_failed'
    }
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $searcher.ServerSelection = 0
        $searcher.Online = $online
        $searcher.CanAutomaticallyUpgradeService = $false
        $searcher.IncludePotentiallySupersededUpdates = $false
        $found = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        $code = [int]$found.ResultCode
        if ($code -notin @(2, 3)) { throw 'Search incomplete' }
        $count = [int]$found.Updates.Count
        if ($count -lt 0 -or $count -gt 100000) { throw 'Update count invalid' }
        $rows = @()
        for ($index = 0; $index -lt [Math]::Min($count, 200); $index++) {
            $update = $found.Updates.Item($index)
            if ($update.IsInstalled -or $update.IsHidden) { throw 'Unexpected update scope' }
            $categories = @()
            foreach ($category in $update.Categories) {
                $categories += @{
                    id=[string]$category.CategoryID; name=(SafeText $category.Name 500)
                    type=(SafeText $category.Type 64)
                }
                if ($categories.Count -gt 100) { throw 'Category count invalid' }
            }
            $kbs = @($update.KBArticleIDs | ForEach-Object { 'KB' + [string]$_ })
            if ($kbs.Count -gt 64) { throw 'KB count invalid' }
            $optional = $null
            $mandatory = $null
            try { if ($null -ne $update.BrowseOnly) { $optional = [bool]$update.BrowseOnly } } catch {}
            try { if ($null -ne $update.IsMandatory) { $mandatory = [bool]$update.IsMandatory } } catch {}
            $rows += @{
                update_id=[string]$update.Identity.UpdateID; revision=[int]$update.Identity.RevisionNumber
                title=(SafeText $update.Title 1000); kbs=$kbs; categories=$categories
                msrc_severity=(SafeText $update.MsrcSeverity 32)
                is_hidden=[bool]$update.IsHidden; is_installed=[bool]$update.IsInstalled
                is_optional=$optional; is_mandatory=$mandatory
            }
        }
        try {
            $system = New-Object -ComObject Microsoft.Update.SystemInfo
            $output.reboot_required = [bool]$system.RebootRequired
        } catch {}
        $output.result_code = $code
        $output.total = $count
        $output.items = $rows
        $output.truncated = $count -gt $rows.Count
        $output.status = if ($code -eq 2 -and !$output.truncated) {'complete'} else {'partial'}
        $output.Remove('error_code')
    } catch {
        # Never return COM exceptions, server URLs, account names or raw stderr.
    }
    return $output
}
$job = $null
$result = $null
$timedOut = $false
try {
    # Production always uses the configured online source. Native CI invokes
    # the exact worker separately with false, never a live update-service search.
    $job = Start-Job -ScriptBlock $worker -ArgumentList $true
    if (Wait-Job -Job $job -Timeout 60) {
        $result = Receive-Job -Job $job -ErrorAction Stop
    } else {
        $timedOut = $true
    }
} catch {
} finally {
    if ($job) {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
}
if (!$result) {
    $result = @{
        schema_version=1; source='windows-update-agent'; mode='online'; server_selection='default'
        queried_at=[DateTime]::UtcNow.ToString('o'); status=$(if ($timedOut) {'timeout'} else {'unavailable'}); result_code=$null
        total=0; items=@(); truncated=$false; hidden_updates='not_assessed'; drivers='not_assessed'
        superseded='excluded'; reboot_required=$null; error_code=$(if ($timedOut) {'timeout'} else {'update_query_failed'})
    }
}
$result | ConvertTo-Json -Depth 8 -Compress
