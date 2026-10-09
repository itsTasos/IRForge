param(
    [ValidateSet('Debug','Release')][string]$Configuration='Release',
    [string]$ToolchainDirectory='',
    [switch]$Tests,
    [switch]$Coverage,
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
    foreach($irforgeTool in @('g++','cmake','ctest','ninja')) {
        if(!(Get-Command $irforgeTool -ErrorAction SilentlyContinue)) {
            throw "Missing $irforgeTool. Use portable w64devkit (C++/CMake/Ninja); Visual Studio is unnecessary."
        }
    }
    $irforgeTarget=(& g++ -dumpmachine).Trim()
    if($LASTEXITCODE -or $irforgeTarget -ne 'x86_64-w64-mingw32') {
        throw "Expected x64 MinGW g++; found target '$irforgeTarget'."
    }
    $irforgePreset=if($Configuration -eq 'Debug') {'mingw-debug'} else {'mingw'}
    $irforgeBuildPreset=if($Configuration -eq 'Debug') {'debug'} else {'release'}
    $irforgeIncludeTests=$Tests -or $Coverage
    $irforgeConfigureArgs=@('--preset',$irforgePreset,"-DBUILD_TESTING=$(if($irforgeIncludeTests){'ON'}else{'OFF'})")
    if($Coverage){$irforgeConfigureArgs+='-DIRFORGE_COVERAGE=ON'}
    if($env:IRFORGE_TEST_PYTHON) {
        $irforgeConfigureArgs+="-DIRFORGE_TEST_PYTHON=$env:IRFORGE_TEST_PYTHON"
    }
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
    & "$PSScriptRoot/bootstrap.ps1" -IncludeTests:$irforgeIncludeTests
    & cmake @irforgeConfigureArgs
    if($LASTEXITCODE) {throw 'Configure failed'}
    cmake --build --preset $irforgeBuildPreset --parallel 4
    if($LASTEXITCODE) {throw 'Build failed'}
    & "$PSScriptRoot/deploy-runtime.ps1" -BuildDirectory "build/$irforgePreset"
    if($irforgeIncludeTests) {
        ctest --preset $irforgeBuildPreset
        if($LASTEXITCODE) {throw 'Tests failed'}
    }
    Write-Host "Executable: build/$irforgePreset/irforge.exe"
} finally {
    $env:Path=$irforgeOriginalPath
    Pop-Location
}
