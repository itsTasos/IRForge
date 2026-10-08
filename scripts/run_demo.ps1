param([string]$Executable='build/mingw/irforge.exe',[int]$DurationSeconds=60,[switch]$Replay,[switch]$AllowDegraded)
$ErrorActionPreference='Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    $output=Join-Path 'out' ('demo-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
    if($Replay) {
        & $Executable replay --events tests/fixtures/suspicious_chain.jsonl --rules rules --output $output
    } else {
        $arguments=@('monitor','--config','config/default.json','--rules','rules','--output',$output,'--duration-seconds',"$DurationSeconds")
        if($AllowDegraded) {$arguments+='--allow-degraded'}
        & $Executable @arguments
    }
    if($LASTEXITCODE) {throw "IRForge exited with $LASTEXITCODE"}
    Write-Host "Logs: $output"
} finally {Pop-Location}
