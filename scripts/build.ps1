param(
    [ValidateSet('Debug','Release')][string]$Configuration='Release',
    [string]$ToolchainDirectory='',
    [switch]$MinGW # Retained for compatibility; MinGW is always the default.
)
$ErrorActionPreference='Stop'
$irforgeOriginalPath=$env:Path
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    if($ToolchainDirectory) {
        $irforgeBin=Join-Path $ToolchainDirectory 'bin'
        if(!(Test-Path -LiteralPath (Join-Path $irforgeBin 'g++.exe'))) {
            throw "Expected g++.exe in $irforgeBin. Pass the extracted w64devkit directory."
        }
        $env:Path="$irforgeBin;$env:Path"
    } elseif(!(Get-Command g++ -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath 'C:\w64devkit\bin\g++.exe')) {
        $env:Path="C:\w64devkit\bin;$env:Path"
    }
    foreach($irforgeTool in @('g++','cmake','ctest','ninja','git')) {
        if(!(Get-Command $irforgeTool -ErrorAction SilentlyContinue)) {
            throw "Missing $irforgeTool. Use portable w64devkit (C++/CMake/Ninja) and Git; Visual Studio is unnecessary."
        }
    }
    $irforgeTarget=(& g++ -dumpmachine).Trim()
    if($LASTEXITCODE -or $irforgeTarget -ne 'x86_64-w64-mingw32') {
        throw "Expected x64 MinGW g++; found target '$irforgeTarget'."
    }
    $irforgePreset=if($Configuration -eq 'Debug') {'mingw-debug'} else {'mingw'}
    $irforgeBuildPreset=if($Configuration -eq 'Debug') {'debug'} else {'release'}
    $irforgeConfigureArgs=@('--preset',$irforgePreset)
    # Reuse already fetched release sources for an offline Debug build, when present.
    if($Configuration -eq 'Debug') {
        foreach($irforgeDependency in @('JSON','CATCH2')) {
            $irforgeDependencyPath=Join-Path (Get-Location) ('build/mingw/_deps/'+$irforgeDependency.ToLower()+'-src')
            if(Test-Path -LiteralPath (Join-Path $irforgeDependencyPath 'CMakeLists.txt')) {
                $irforgeConfigureArgs+="-DFETCHCONTENT_SOURCE_DIR_${irforgeDependency}=$irforgeDependencyPath"
            }
        }
    }
    Write-Host "Building $Configuration using MinGW: $((Get-Command g++).Source)"
    & cmake @irforgeConfigureArgs
    if($LASTEXITCODE) {throw 'Configure failed'}
    cmake --build --preset $irforgeBuildPreset --parallel 4
    if($LASTEXITCODE) {throw 'Build failed'}
    ctest --preset $irforgeBuildPreset
    if($LASTEXITCODE) {throw 'Tests failed'}
    Write-Host "Executable: build/$irforgePreset/irforge.exe"
} finally {
    $env:Path=$irforgeOriginalPath
    Pop-Location
}
