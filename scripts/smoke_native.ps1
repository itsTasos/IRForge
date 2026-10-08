param([string]$Executable='build/mingw/irforge.exe')
# Read-only native smoke: open loopback sockets, collect for 10 seconds, modify no Registry data.
$ErrorActionPreference='Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
$irforgeListener4=$null; $irforgeListener6=$null; $irforgeClients=@(); $irforgeAccepted=@()
try {
    $irforgeBase=Join-Path (Get-Location) ('build/native-'+[guid]::NewGuid().ToString('N'))
    $irforgeProcess=Start-Process -FilePath (Resolve-Path $Executable) -ArgumentList @('monitor','--config','config/default.json','--duration-seconds','10','--allow-degraded','--quiet','--output',('"'+$irforgeBase+'"')) -PassThru -WindowStyle Hidden -RedirectStandardOutput ($irforgeBase+'.stdout.txt') -RedirectStandardError ($irforgeBase+'.stderr.txt')
    Start-Sleep -Seconds 2
    $irforgePeak=0
    foreach($irforgeAddress in @([Net.IPAddress]::Loopback,[Net.IPAddress]::IPv6Loopback)) {
        $irforgeListener=[Net.Sockets.TcpListener]::new($irforgeAddress,0)
        $irforgeListener.Start()
        if($irforgeAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {$irforgeListener4=$irforgeListener} else {$irforgeListener6=$irforgeListener}
        $irforgeClient=[Net.Sockets.TcpClient]::new($irforgeAddress.AddressFamily)
        $irforgeClient.Connect($irforgeAddress,$irforgeListener.LocalEndpoint.Port)
        $irforgeClients+=$irforgeClient
        $irforgeAccepted+=$irforgeListener.AcceptTcpClient()
    }
    $irforgeCommand=Start-Process -FilePath $env:ComSpec -ArgumentList '/c exit 0' -PassThru -WindowStyle Hidden
    $irforgeCommand.WaitForExit()
    foreach($irforgeSample in 1..3) {
        Start-Sleep -Seconds 1
        $irforgeProcess.Refresh()
        if(!$irforgeProcess.HasExited) {$irforgePeak=[Math]::Max($irforgePeak,$irforgeProcess.WorkingSet64)}
    }
    foreach($irforgeClient in $irforgeClients+$irforgeAccepted) {$irforgeClient.Dispose()}
    $irforgeListener4.Stop(); $irforgeListener6.Stop()
    $irforgeProcess.WaitForExit()
    if($irforgeProcess.ExitCode -ne 0) {throw "Native smoke failed: $($irforgeProcess.ExitCode)"}
    $irforgeEvents=@(Get-Content -LiteralPath (Join-Path $irforgeBase 'events.jsonl') | ForEach-Object {$_ | ConvertFrom-Json})
    $irforgeLoops=@($irforgeEvents | Where-Object {$_.event_type -eq 'tcp_connection_observed' -and $_.payload.owner_pid -eq $PID -and $_.payload.state -eq 'ESTABLISHED' -and $_.payload.remote_address -in @('127.0.0.1','::1') -and !$_.payload.first_snapshot})
    $irforgeClosed=@($irforgeEvents | Where-Object {$_.event_type -eq 'tcp_connection_closed' -and $_.payload.owner_pid -eq $PID -and $_.payload.remote_address -in @('127.0.0.1','::1')})
    $irforgeFamilies=@($irforgeLoops.payload.protocol | Sort-Object -Unique)
    if($irforgeFamilies.Count -ne 2 -or $irforgeClosed.Count -lt 2) {throw 'Did not observe both loopback address families and disappearance'}
    $irforgeResult=[ordered]@{output_directory=$irforgeBase;elapsed_seconds=10;sampled_peak_working_set_bytes=$irforgePeak;cpu_seconds=$irforgeProcess.TotalProcessorTime.TotalSeconds;owner_pid=$PID;established_loopback_observations=$irforgeLoops.Count;closed_loopback_observations=$irforgeClosed.Count;families=$irforgeFamilies;exit_code=$irforgeProcess.ExitCode}
    $irforgeResult | ConvertTo-Json | Set-Content -LiteralPath ($irforgeBase+'.result.json') -Encoding utf8
    $irforgeResult | ConvertTo-Json
} finally {
    foreach($irforgeClient in $irforgeClients+$irforgeAccepted) {$irforgeClient.Dispose()}
    if($irforgeListener4) {$irforgeListener4.Stop()}
    if($irforgeListener6) {$irforgeListener6.Stop()}
    Pop-Location
}
