$ErrorActionPreference = 'Stop'
$collector = Join-Path $PSScriptRoot '..\app\services\windows_update_inventory.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $collector, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Windows update collector has syntax errors' }
$builder = Join-Path $PSScriptRoot '..\app\services\windows_inventory_command.py'
$manifest = (& python -I $builder --mode windows_updates) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Fixed update command builder failed' }
$commandLine = $manifest.executable + ' ' + ($manifest.arguments -join ' ')
if ($commandLine.Length -ge 8000) { throw 'Native update launch exceeds the command budget' }
$bootstrap = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($manifest.arguments[-1]))
$compressed = [regex]::Match($bootstrap, "FromBase64String\('([A-Za-z0-9+/=]+)'\)")
if (!$compressed.Success) { throw 'Production update launcher does not contain the fixed source' }
$memory = [IO.MemoryStream]::new([Convert]::FromBase64String($compressed.Groups[1].Value), $false)
$gzip = [IO.Compression.GZipStream]::new($memory, [IO.Compression.CompressionMode]::Decompress)
$reader = [IO.StreamReader]::new($gzip, [Text.UTF8Encoding]::new($false, $true))
try {
    $decoded = $reader.ReadToEnd()
    $expected = '$ccvmMode = ''windows_updates''' + "`n" +
        [IO.File]::ReadAllText($collector, [Text.UTF8Encoding]::new($false, $true))
    if ($decoded -cne $expected) { throw 'Production WUA compression changed source bytes/newlines' }
} finally {
    $reader.Dispose(); $gzip.Dispose(); $memory.Dispose()
}
Write-Output "Native production WUA command budget and exact source passed; chars=$($commandLine.Length)"
$workerAssignment = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq '$worker'
}, $true)
if (!$workerAssignment) { throw 'Fixed WUA worker was not found' }
$workerText = $workerAssignment.Right.Extent.Text.Trim()
if (!$workerText.StartsWith('{') -or !$workerText.EndsWith('}')) {
    throw 'Unexpected fixed WUA worker boundary'
}
$worker = [ScriptBlock]::Create($workerText.Substring(1, $workerText.Length - 2))

# Actual native COM, using only local cached metadata. This test NEVER runs the
# production online entry point against an update service or a production host.
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$searcher.ServerSelection = 0
$searcher.Online = $false
$searcher.CanAutomaticallyUpgradeService = $false
$searcher.IncludePotentiallySupersededUpdates = $false
if ($searcher.Online -ne $false -or $searcher.ServerSelection -ne 0) {
    throw 'Native WUA configured-source cached options differ'
}
$job = $null
try {
    $job = Start-Job -ScriptBlock $worker -ArgumentList $false
    if (Wait-Job -Job $job -Timeout 60) {
        $cached = Receive-Job -Job $job -ErrorAction Stop
        if ($cached.schema_version -ne 1 -or $cached.mode -ne 'cached' -or
            $cached.status -notin @('complete', 'partial', 'unavailable') -or
            $cached.server_selection -ne 'default' -or $cached.items.Count -gt 200) {
            throw 'Native cached WUA worker returned an invalid envelope'
        }
        Write-Output "Native WUA cached-only worker passed; status=$($cached.status)"
    } else {
        Write-Output 'Native WUA cached-only worker reached its bounded timeout; cache not assessed'
    }
} finally {
    if ($job) {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
}

# Execute the exact production main/worker with a synthetic local COM provider
# and job lifecycle. No system policy, service, registry or update is changed.
foreach ($scenario in @('complete', 'partial', 'truncated', 'query-failure',
                        'timeout', 'launch-failure', 'unknown-optional')) {
    & {
        param($collectorPath, $scenario)
        $script:fixtureScenario = $scenario
        $script:stopped = 0
        $script:removed = 0
        function Start-Job {
            param([scriptblock]$ScriptBlock, [object[]]$ArgumentList)
            if ($ArgumentList.Count -ne 1 -or $ArgumentList[0] -ne $true) {
                throw 'Production query unexpectedly changed to cached or custom source mode'
            }
            if ($scenario -eq 'launch-failure') { throw 'private-account synthetic-secret' }
            function New-Object {
                param([string]$ComObject)
                if ($ComObject -eq 'Microsoft.Update.SystemInfo') {
                    return [pscustomobject]@{RebootRequired=$true}
                }
                if ($ComObject -ne 'Microsoft.Update.Session') {
                    throw 'Unexpected COM provider'
                }
                $count = if ($script:fixtureScenario -eq 'truncated') {201} else {1}
                $rows = @()
                foreach ($index in 1..$count) {
                    $row = [pscustomobject]@{
                        IsInstalled=$false; IsHidden=$false; IsMandatory=$false
                        BrowseOnly=$false; Title='Fixture update'; KBArticleIDs=@('1234567')
                        MsrcSeverity='Important'
                        Identity=[pscustomobject]@{
                            UpdateID=('11111111-1111-4111-8111-{0:d12}' -f $index)
                            RevisionNumber=201
                        }
                        Categories=@([pscustomobject]@{
                            CategoryID='0fa1201d-4330-4fa8-8ae9-b877473b6441'
                            Name='Localized fixture security category'; Type='UpdateClassification'
                        })
                    }
                    if ($script:fixtureScenario -eq 'unknown-optional') {
                        $row.PSObject.Properties.Remove('BrowseOnly')
                    }
                    $rows += $row
                }
                $updates = [pscustomobject]@{Count=$count; Rows=$rows}
                $updates | Add-Member ScriptMethod Item {param($index) return $this.Rows[$index]}
                $search = [pscustomobject]@{
                    ServerSelection=$null; Online=$null; CanAutomaticallyUpgradeService=$null
                    IncludePotentiallySupersededUpdates=$null; Updates=$updates
                }
                $search | Add-Member ScriptMethod Search {
                    param($criteria)
                    if ($this.ServerSelection -ne 0 -or $this.Online -ne $true -or
                        $this.CanAutomaticallyUpgradeService -ne $false -or
                        $this.IncludePotentiallySupersededUpdates -ne $false -or
                        $criteria -ne "IsInstalled=0 and Type='Software' and IsHidden=0") {
                        throw 'Unexpected WUA source/options/criteria'
                    }
                    if ($script:fixtureScenario -eq 'query-failure') {
                        throw 'private-account synthetic-secret source-url'
                    }
                    $code = if ($script:fixtureScenario -eq 'partial') {3} else {2}
                    return [pscustomobject]@{ResultCode=$code; Updates=$this.Updates}
                }
                $session = [pscustomobject]@{Searcher=$search}
                $session | Add-Member ScriptMethod CreateUpdateSearcher {return $this.Searcher}
                return $session
            }
            $data = if ($scenario -eq 'timeout') {$null} else {& $ScriptBlock $true}
            return [pscustomobject]@{Data=$data}
        }
        function Wait-Job {
            param($Job, [int]$Timeout)
            if ($Timeout -ne 60) { throw 'Production WUA deadline changed' }
            if ($scenario -ne 'timeout') { return $Job }
        }
        function Receive-Job {
            [CmdletBinding()]
            param($Job)
            return $Job.Data
        }
        function Stop-Job {
            [CmdletBinding()]
            param($Job)
            $script:stopped++
        }
        function Remove-Job {
            [CmdletBinding()]
            param($Job, [switch]$Force)
            if (!$Force) { throw 'Server job must be removed' }
            $script:removed++
        }
        $raw = & $collectorPath
        if ($raw -match 'private-account|synthetic-secret|source-url') {
            throw 'Raw provider exception leaked into evidence'
        }
        $data = $raw | ConvertFrom-Json
        if ($data.mode -ne 'online' -or $data.server_selection -ne 'default' -or
            $data.hidden_updates -ne 'not_assessed' -or $data.drivers -ne 'not_assessed' -or
            $data.superseded -ne 'excluded') {
            throw 'Production query lost configured-source coverage boundaries'
        }
        $expected = switch ($scenario) {
            'partial' {'partial'}
            'truncated' {'partial'}
            'query-failure' {'unavailable'}
            'timeout' {'timeout'}
            'launch-failure' {'unavailable'}
            default {'complete'}
        }
        if ($data.status -ne $expected) { throw "Incorrect update search status: $scenario" }
        if ($scenario -eq 'truncated' -and
            ($data.total -ne 201 -or $data.items.Count -ne 200 -or !$data.truncated)) {
            throw 'Production WUA item cap or truncation evidence changed'
        }
        if ($scenario -eq 'unknown-optional' -and $null -ne $data.items[0].is_optional) {
            throw 'Unknown optional status was converted into a required-update claim'
        }
        if ($scenario -ne 'launch-failure' -and ($script:stopped -ne 1 -or $script:removed -ne 1)) {
            throw 'Production WUA server job was not cleaned up'
        }
        Write-Output "Synthetic production WUA query passed: $scenario"
    } $collector $scenario
}
