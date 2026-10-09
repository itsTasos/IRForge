param([string]$SevenZip='', [switch]$Installer, [switch]$IncludeTests)
$ErrorActionPreference='Stop'
$irforgeRoot=Split-Path $PSScriptRoot -Parent
$irforgeDeps=Join-Path $irforgeRoot 'build/dependencies'
New-Item -ItemType Directory -Path $irforgeDeps -Force | Out-Null
$irforgeLock=Get-Content -LiteralPath (Join-Path $irforgeRoot 'dependencies.lock.json') -Raw | ConvertFrom-Json
if(!$SevenZip){$irforgeSeven=Get-Command 7z -ErrorAction SilentlyContinue;if($irforgeSeven){$SevenZip=$irforgeSeven.Source}else{$SevenZip='C:\Program Files\7-Zip\7z.exe'}}
if(!(Test-Path -LiteralPath $SevenZip)){throw '7-Zip is required to extract pinned Qt archives. Visual Studio is unnecessary.'}
function Restore-Archive($irforgeDependency){
    $irforgeArchive=Join-Path $irforgeDeps $irforgeDependency.file
    if(!(Test-Path -LiteralPath $irforgeArchive)){
        if($irforgeDependency.name -eq 'clang-format'){
            $irforgeMetadata=Invoke-RestMethod 'https://pypi.org/pypi/clang-format/19.1.7/json'
            $irforgeRelease=$irforgeMetadata.urls | Where-Object {$_.filename -eq $irforgeDependency.file} | Select-Object -First 1
            if(!$irforgeRelease -or $irforgeRelease.digests.sha256 -ne $irforgeDependency.sha256){throw 'Pinned formatter source hash mismatch'}
            $irforgeUrl=$irforgeRelease.url
        }else{$irforgeUrl=$irforgeDependency.url}
        Invoke-WebRequest -UseBasicParsing -Uri $irforgeUrl -OutFile $irforgeArchive
    }
    if((Get-FileHash -LiteralPath $irforgeArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $irforgeDependency.sha256){throw "Checksum mismatch: $irforgeArchive"}
    return $irforgeArchive
}
foreach($irforgeDependency in $irforgeLock.archives){
    if($irforgeDependency.name -eq 'catch2' -and !$IncludeTests){continue}
    $irforgeArchive=Restore-Archive $irforgeDependency
    switch($irforgeDependency.name){
        'yara-source' {if(!(Test-Path "$irforgeDeps/yara-source/yara-x-1.21.0/Cargo.lock")){Expand-Archive -LiteralPath $irforgeArchive -DestinationPath "$irforgeDeps/yara-source" -Force}}
        'yara' {if(!(Test-Path (Join-Path $irforgeDeps 'yara/yara_x.h'))){Expand-Archive -LiteralPath $irforgeArchive -DestinationPath (Join-Path $irforgeDeps 'yara') -Force}}
        'qt' {if(!(Test-Path (Join-Path $irforgeDeps 'qt/bin/qmake.exe'))){& $SevenZip x $irforgeArchive "-o$irforgeDeps/qt-extract" -y | Out-Null;if($LASTEXITCODE){throw 'Qt extraction failed'};$irforgeQmake=Get-ChildItem "$irforgeDeps/qt-extract" -Recurse -Filter qmake.exe | Select-Object -First 1;$irforgeQtRoot=Split-Path (Split-Path $irforgeQmake.FullName -Parent) -Parent;Copy-Item -LiteralPath $irforgeQtRoot -Destination "$irforgeDeps/qt" -Recurse}}
        'qt-runtime' {if(!(Test-Path "$irforgeDeps/qt/bin/libstdc++-6.dll")){& $SevenZip x $irforgeArchive "-o$irforgeDeps/qt-runtime-extract" -y | Out-Null;if($LASTEXITCODE){throw 'Qt compiler runtime extraction failed'};foreach($irforgeDll in @('libgcc_s_seh-1.dll','libstdc++-6.dll','libwinpthread-1.dll')){$irforgeRuntime=Get-ChildItem "$irforgeDeps/qt-runtime-extract" -Recurse -Filter $irforgeDll | Select-Object -First 1;Copy-Item -LiteralPath $irforgeRuntime.FullName -Destination "$irforgeDeps/qt/bin/$irforgeDll"}}}
        'clang-format' {if(!(Test-Path "$irforgeDeps/clang-format/clang_format/data/bin/clang-format.exe")){& $SevenZip x $irforgeArchive "-o$irforgeDeps/clang-format" -y | Out-Null;if($LASTEXITCODE){throw 'Formatter extraction failed'}}}
        'qt-source' {if(!(Test-Path "$irforgeDeps/qt-source/qtbase-everywhere-src-6.8.3/LICENSES")){& $SevenZip x $irforgeArchive "-o$irforgeDeps/qt-source" -y | Out-Null;if($LASTEXITCODE){throw 'Qt source extraction failed'};& $SevenZip x "$irforgeDeps/qt-source/qtbase-source.tar" "-o$irforgeDeps/qt-source" -y | Out-Null;if($LASTEXITCODE){throw 'Qt source tar extraction failed'}}}
    }
    Write-Host "Verified $($irforgeDependency.name) $($irforgeDependency.version)"
}
if($Installer){
    $env:DOTNET_CLI_TELEMETRY_OPTOUT='1';$env:DOTNET_GENERATE_ASPNET_CERTIFICATE='false'
    $env:DOTNET_CLI_HOME=Join-Path $irforgeRoot 'build/dotnet-home';$env:NUGET_PACKAGES=Join-Path $irforgeDeps 'nuget'
    if(!(Test-Path "$irforgeDeps/wix/wix.exe")){dotnet tool install wix --tool-path "$irforgeDeps/wix" --version 6.0.2;if($LASTEXITCODE){throw 'WiX restore failed'}}
    Push-Location $irforgeRoot
    try{& "$irforgeDeps/wix/wix.exe" extension add WixToolset.UI.wixext/6.0.2;if($LASTEXITCODE){throw 'WiX UI extension restore failed'}}finally{Pop-Location}
}
