param([string]$BuildDirectory='build/mingw')
$ErrorActionPreference='Stop'
$irforgeRoot=Split-Path $PSScriptRoot -Parent
$irforgeBuild=(Resolve-Path (Join-Path $irforgeRoot $BuildDirectory)).Path
$irforgeQt=Join-Path $irforgeRoot 'build/dependencies/qt/bin'
foreach($irforgeExe in @('irforge.exe','irforge_gui.exe','irforge_collector.exe')){
    & (Join-Path $irforgeQt 'windeployqt.exe') --release --no-translations --no-system-d3d-compiler --no-opengl-sw --dir $irforgeBuild (Join-Path $irforgeBuild $irforgeExe)
    if($LASTEXITCODE){throw "Qt runtime deployment failed: $irforgeExe"}
}
foreach($irforgeDll in @('libgcc_s_seh-1.dll','libstdc++-6.dll','libwinpthread-1.dll')){Copy-Item -LiteralPath (Join-Path $irforgeQt $irforgeDll) -Destination $irforgeBuild -Force}
Copy-Item -LiteralPath (Join-Path $irforgeBuild 'irforge_gui.exe') -Destination (Join-Path $irforgeBuild 'IRForgeUI.exe') -Force
