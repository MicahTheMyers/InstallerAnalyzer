param([string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference='Stop'
$source=Get-Content -LiteralPath (Join-Path $ProjectRoot 'InstallerAnalyzer\Services\SandboxIssRecorder.cs') -Raw
$body=[regex]::Match($source,'(?s)function Expand-TrackedProcessTree\(.*?\r?\n}\r?\n').Value
if(-not $body){throw 'Process tree function not found.'}
Invoke-Expression $body

$start=[datetime]::UtcNow
$tracked=New-Object 'System.Collections.Generic.HashSet[int]'
[void]$tracked.Add(1424)
$births=@{1424=$start}
function New-ProcessRow([int]$id,[int]$parent,[int]$offset) {
    [pscustomobject]@{ProcessId=$id;ParentProcessId=$parent;CreationDate=$start.AddSeconds($offset)}
}

$snapshot=@(
    (New-ProcessRow 1324 1424 -90)
    (New-ProcessRow 2016 1424 -90)
    (New-ProcessRow 4288 2016 -89)
    (New-ProcessRow 4040 3000 2)
    (New-ProcessRow 3000 1424 1)
)
$null=Expand-TrackedProcessTree $snapshot $tracked $births
if($tracked.Count -ne 3 -or -not $tracked.Contains(3000) -or -not $tracked.Contains(4040)){
    throw 'Tracking must include the installer descendants and exclude children older than the installer.'
}

$snapshot=@(
    (New-ProcessRow 1424 4 4)
    (New-ProcessRow 3000 4 4)
    (New-ProcessRow 4040 3000 2)
    (New-ProcessRow 5020 1424 5)
    (New-ProcessRow 5024 3000 5)
)
$active=@(Expand-TrackedProcessTree $snapshot $tracked $births | Where-Object {$tracked.Contains([int]$_.ProcessId)})
if($active.Count -ne 1 -or $active[0].ProcessId -ne 4040 -or $tracked.Contains(5020) -or $tracked.Contains(5024)){
    throw 'Recycled process IDs and their new children must not join the installer tree.'
}
'PASS installer process tracking rejects stale children and recycled IDs while retaining a surviving descendant.'
