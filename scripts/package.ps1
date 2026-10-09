param([string]$BuildDirectory='build/mingw',[string]$Version='1.0.0-dev',[switch]$SkipMsi)
$ErrorActionPreference='Stop'
$irforgeRoot=Split-Path $PSScriptRoot -Parent
Push-Location $irforgeRoot
try{
    $irforgeBuild=(Resolve-Path -LiteralPath $BuildDirectory).Path
    $irforgeStage=Join-Path $irforgeRoot ('build/package-'+[guid]::NewGuid().ToString('N'))
    Set-Content build/package-stage-path.txt $irforgeStage
    New-Item -ItemType Directory -Path $irforgeStage | Out-Null
    foreach($irforgeFile in @('irforge.exe','irforge_gui.exe','irforge_collector.exe','yara_x_capi.dll')){
        Copy-Item -LiteralPath (Join-Path $irforgeBuild $irforgeFile) -Destination $irforgeStage
    }
    # Only deployed runtime DLLs/plugins; no tests, private PKI, recordings or developer executables.
    Get-ChildItem -LiteralPath $irforgeBuild -Filter '*.dll' | ForEach-Object {Copy-Item -LiteralPath $_.FullName -Destination $irforgeStage}
    foreach($irforgeDirectory in @('platforms','tls','networkinformation','styles','imageformats')){
        if(Test-Path (Join-Path $irforgeBuild $irforgeDirectory)){Copy-Item -LiteralPath (Join-Path $irforgeBuild $irforgeDirectory) -Destination $irforgeStage -Recurse}
    }
    Copy-Item -LiteralPath (Join-Path $irforgeStage 'irforge_gui.exe') -Destination (Join-Path $irforgeStage 'IRForgeUI.exe')
    foreach($irforgeDirectory in @('config','rules','schemas','assets/attack_dataset')){
        $irforgeDestination=Join-Path $irforgeStage $irforgeDirectory
        New-Item -ItemType Directory -Path (Split-Path $irforgeDestination -Parent) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $irforgeRoot $irforgeDirectory) -Destination $irforgeDestination -Recurse
    }
    New-Item -ItemType Directory -Path (Join-Path $irforgeStage 'docs') | Out-Null
    foreach($irforgeDoc in @('architecture.md','operations.md','limitations.md','eventlog.md','remote.md','rule-format.md','sigma-subset.md')){
        Copy-Item -LiteralPath (Join-Path $irforgeRoot "docs/$irforgeDoc") -Destination (Join-Path $irforgeStage 'docs')
    }
    foreach($irforgeFile in @('README.md','LICENSE','PRIVACY.md','SECURITY.md','THIRD_PARTY_NOTICES.md','dependencies.lock.json','RELEASE_NOTES.md')){
        Copy-Item -LiteralPath (Join-Path $irforgeRoot $irforgeFile) -Destination $irforgeStage
    }
    $irforgeLicenses=Join-Path $irforgeStage 'licenses'
    New-Item -ItemType Directory -Path $irforgeLicenses | Out-Null
    Copy-Item -LiteralPath 'build/dependencies/qt-source/qtbase-everywhere-src-6.8.3/LICENSES' -Destination (Join-Path $irforgeLicenses 'qt') -Recurse
    $irforgeThirdParty=Get-ChildItem 'build/dependencies/qt-source/qtbase-everywhere-src-6.8.3/src/3rdparty' -Recurse -File | Where-Object {$_.Name -match '^(LICENSE|COPYING|COPYRIGHT)' -or $_.Name -eq 'qt_attribution.json'}
    foreach($irforgeLicense in $irforgeThirdParty){$irforgeRelative=$irforgeLicense.FullName.Substring((Resolve-Path 'build/dependencies/qt-source/qtbase-everywhere-src-6.8.3/src/3rdparty').Path.Length+1);$irforgeTarget=Join-Path (Join-Path $irforgeLicenses 'qt-thirdparty') $irforgeRelative;New-Item -ItemType Directory -Path (Split-Path $irforgeTarget -Parent) -Force | Out-Null;Copy-Item -LiteralPath $irforgeLicense.FullName -Destination $irforgeTarget}
    foreach($irforgeDependency in @(@('json','LICENSE.MIT'),@('tinyxml2','LICENSE.txt'),@('yamlcpp','LICENSE'))){Copy-Item -LiteralPath (Join-Path $irforgeBuild ('_deps/'+$irforgeDependency[0]+'-src/'+$irforgeDependency[1])) -Destination (Join-Path $irforgeLicenses ($irforgeDependency[0]+'.txt'))}
    Copy-Item -LiteralPath 'assets/licenses/yara-x-BSD-3-Clause.txt' -Destination $irforgeLicenses
    Copy-Item -LiteralPath 'assets/licenses/gcc-COPYING.RUNTIME' -Destination $irforgeLicenses
    Copy-Item -LiteralPath 'assets/licenses/gcc-COPYING3' -Destination $irforgeLicenses
    Copy-Item -LiteralPath 'assets/licenses/mingw-w64-COPYING' -Destination $irforgeLicenses
    Copy-Item -LiteralPath 'assets/licenses/yara-transitive' -Destination $irforgeLicenses -Recurse
    $irforgeManifest=@{schema_version=1;application='IRForge';version=$Version;unsigned=$true;files=@()}
    Get-ChildItem -LiteralPath $irforgeStage -Recurse -File | Sort-Object FullName | ForEach-Object {$irforgeManifest.files+=@{path=$_.FullName.Substring($irforgeStage.Length+1).Replace('\','/');bytes=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}}
    $irforgeManifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $irforgeStage 'package-manifest.json') -Encoding utf8
    New-Item -ItemType Directory -Path dist -Force | Out-Null
    $irforgeArchive=Join-Path $irforgeRoot "dist/IRForge-$Version-windows-x64.zip"
    if(Test-Path -LiteralPath $irforgeArchive){throw 'Release artifact already exists; choose a new version/path rather than overwrite evidence'}
    Compress-Archive -Path "$irforgeStage/*" -DestinationPath $irforgeArchive -CompressionLevel Optimal
    Copy-Item -LiteralPath 'build/dependencies/qtbase-source.tar.xz' -Destination "dist/qtbase-corresponding-source-6.8.3.tar.xz" -Force
    Copy-Item -LiteralPath 'build/dependencies/yara-source.zip' -Destination 'dist/yara-x-corresponding-source-1.21.0.zip' -Force
    # Retain corresponding source for every pinned transitive crate, including MPL portions.
    $irforgeCrateSource='dist/yara-x-locked-crate-sources-1.21.0.zip'
    if(!(Test-Path -LiteralPath $irforgeCrateSource)){
        Compress-Archive -Path 'build/dependencies/crates/*.crate' -DestinationPath $irforgeCrateSource -CompressionLevel Optimal
    }
    if(!$SkipMsi){
        $irforgeBundledPython="$env:USERPROFILE/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe"
        $irforgePython=if($env:IRFORGE_PYTHON){$env:IRFORGE_PYTHON}elseif($env:IRFORGE_TEST_PYTHON){$env:IRFORGE_TEST_PYTHON}elseif(Test-Path -LiteralPath $irforgeBundledPython){$irforgeBundledPython}else{(Get-Command python -ErrorAction Stop).Source}
        & $irforgePython scripts/installer.py --stage $irforgeStage --output "dist/IRForge-$Version-windows-x64.msi" --root $irforgeRoot --version $Version
        if($LASTEXITCODE){throw 'MSI generation failed'}
    }
    Get-ChildItem dist -File | Where-Object {$_.Extension -notin @('.txt','.wixpdb')} | ForEach-Object {"$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $($_.Name)"} | Set-Content dist/SHA256SUMS.txt
    Set-Content build/package-stage-path.txt $irforgeStage
    Write-Host "Portable package: $irforgeArchive"
}finally{Pop-Location}
