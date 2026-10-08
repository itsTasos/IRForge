param([string]$Directory='')
# Read saved logs without changing them. An alert is a historical finding, not a host verdict.
$ErrorActionPreference='Stop'
function Format-IrforgeUtc($Value) {
    if(!$Value) {return '(not recorded)'}
    if($Value -is [DateTime]) {return $Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")}
    return [string]$Value
}
if(!$Directory) {
    $irforgeOut=Join-Path (Split-Path $PSScriptRoot -Parent) 'out'
    $irforgeCandidates=@(Get-ChildItem -LiteralPath $irforgeOut -Directory -ErrorAction SilentlyContinue |
        Where-Object {Test-Path -LiteralPath (Join-Path $_.FullName 'session-metadata.json')} |
        Sort-Object LastWriteTime -Descending)
    if(!$irforgeCandidates.Count) {throw 'No saved runs under out. Pass -Directory with a result folder.'}
    $Directory=$irforgeCandidates[0].FullName
}
$irforgePath=(Resolve-Path -LiteralPath $Directory).Path
$irforgeSession=Get-Content -LiteralPath (Join-Path $irforgePath 'session-metadata.json') -Raw -Encoding utf8 | ConvertFrom-Json
$irforgeHealth=Get-Content -LiteralPath (Join-Path $irforgePath 'monitor-health.json') -Raw -Encoding utf8 | ConvertFrom-Json
Write-Host "Results: $irforgePath"
Write-Host "Mode: $($irforgeSession.mode) | Session result: $($irforgeSession.result)"
Write-Host "UTC interval: $(Format-IrforgeUtc $irforgeSession.start_utc) -> $(Format-IrforgeUtc $irforgeSession.stop_utc)"
Write-Host "Last recorded coverage: $($irforgeHealth.coverage) | Queue drops: $($irforgeHealth.queue_drops) | Context evictions: $($irforgeHealth.context_evictions)"
if($irforgeSession.stop_utc) {Write-Host 'This is a completed recording; source health describes the saved run.'}
if($irforgeSession.mode -eq 'replay') {Write-Host 'OFFLINE REPLAY: findings describe fixture/input events, not this machine.'}
foreach($irforgeSource in $irforgeHealth.sources.PSObject.Properties) {
    $irforgeState=$irforgeSource.Value
    Write-Host ("  {0}: {1}; error={2}, lost={3}, decode_errors={4}" -f $irforgeSource.Name,$irforgeState.state,$irforgeState.error_code,$irforgeState.events_lost,$irforgeState.decode_errors)
}
$irforgeCounts=@{}
Get-Content -LiteralPath (Join-Path $irforgePath 'events.jsonl') -Encoding utf8 | ForEach-Object {
    if($_.Trim()) {
        $irforgeEvent=$_ | ConvertFrom-Json
        $irforgeCounts[$irforgeEvent.event_type]=1+$irforgeCounts[$irforgeEvent.event_type]
    }
}
Write-Host 'Recorded events:'
$irforgeCounts.GetEnumerator() | Sort-Object Name | ForEach-Object {Write-Host "  $($_.Name): $($_.Value)"}
# One incident may have multiple escalation records. Display its last recorded alert once.
$irforgeLatest=@{}
$irforgeAlertRecords=0
Get-Content -LiteralPath (Join-Path $irforgePath 'alerts.jsonl') -Encoding utf8 | ForEach-Object {
    if($_.Trim()) {
        $irforgeAlert=$_ | ConvertFrom-Json
        $irforgeLatest[$irforgeAlert.incident_id]=$irforgeAlert
        $irforgeAlertRecords++
    }
}
Write-Host "Alert records: $irforgeAlertRecords | Distinct alerted incidents: $($irforgeLatest.Count)"
if(!$irforgeLatest.Count) {
    Write-Host 'No alerts met the configured threshold during this recording. This does not establish that the machine is clean.'
} else {
    foreach($irforgeAlert in ($irforgeLatest.Values | Sort-Object score -Descending)) {
        Write-Host "  $($irforgeAlert.incident_id): $($irforgeAlert.severity), score=$($irforgeAlert.score), confidence=$($irforgeAlert.confidence)"
        Write-Host "    Rules: $($irforgeAlert.rule_ids -join ', ') | Evidence event IDs: $($irforgeAlert.evidence_event_ids -join ', ')"
        Write-Host "    $($irforgeAlert.explanation)"
    }
    Write-Host 'Alert status and score are snapshots at emission; alerts.jsonl does not persist later expiration/resolution. Investigate evidence before drawing a host-level conclusion.'
}
