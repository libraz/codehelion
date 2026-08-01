# Build real PE images and PDBs, then verify identity-checked source mappings.
# The DLLs are compiler outputs only; codehelion reads their bytes and never
# loads or executes either fixture.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Match {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if (-not (Select-String -LiteralPath $Path -Pattern $Pattern -Quiet)) {
        throw "Expected $Description in $Path"
    }
}

function Invoke-MsvcFixtureBuild {
    param(
        [Parameter(Mandatory = $true)][string]$DeveloperCommand,
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Dll,
        [Parameter(Mandatory = $true)][string]$Pdb,
        [Parameter(Mandatory = $true)][bool]$Mismatch
    )

    $define = if ($Mismatch) { ' /DPE_PDB_MISMATCH=1' } else { '' }
    $command = "call `"$DeveloperCommand`" -no_logo -arch=x64 -host_arch=x64 && cl.exe /nologo /std:c++20 /Zi /Od /LD$define `"$Source`" /link /DEBUG /OUT:`"$Dll`" /PDB:`"$Pdb`""
    & cmd.exe /d /s /c $command
    if ($LASTEXITCODE -ne 0) {
        throw "MSVC fixture build failed with exit code $LASTEXITCODE"
    }
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw "Visual Studio locator is unavailable: $vswhere"
}
$visualStudio = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ([string]::IsNullOrWhiteSpace($visualStudio)) {
    throw 'MSVC C++ build tools are unavailable'
}
$developerCommand = Join-Path $visualStudio 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path -LiteralPath $developerCommand)) {
    throw "Visual Studio developer command is unavailable: $developerCommand"
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("codehelion-pe-fixtures-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null

try {
    $fixtureRoot = Join-Path $temporaryRoot 'fixture'
    New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
    $source = Join-Path $fixtureRoot 'duplicates.cpp'
    Copy-Item -LiteralPath 'fixtures/artifact/pe/duplicates.cpp' -Destination $source

    $variant = Join-Path $fixtureRoot 'build-variant.json'
    @'
{
  "profile": "debug",
  "optimization_level": 0,
  "debug_info": 2,
  "target": "x86_64-pc-windows-msvc",
  "compiler": "cl.exe"
}
'@ | Set-Content -LiteralPath $variant -NoNewline

    $dll = Join-Path $fixtureRoot 'duplicates.dll'
    $pdb = Join-Path $fixtureRoot 'duplicates.pdb'
    Invoke-MsvcFixtureBuild -DeveloperCommand $developerCommand -Source $source -Dll $dll -Pdb $pdb -Mismatch $false

    $mismatchDll = Join-Path $fixtureRoot 'mismatch.dll'
    $mismatchPdb = Join-Path $fixtureRoot 'mismatch.pdb'
    Invoke-MsvcFixtureBuild -DeveloperCommand $developerCommand -Source $source -Dll $mismatchDll -Pdb $mismatchPdb -Mismatch $true

    $database = Join-Path $temporaryRoot 'artifact.sqlite'
    $scan = Join-Path $temporaryRoot 'source-scan.json'
    & cargo run --quiet -p codehelion-cli -- scan $fixtureRoot --mode structural --format json --db $database --output $scan
    if ($LASTEXITCODE -ne 0) {
        throw "Source fixture scan failed with exit code $LASTEXITCODE"
    }
    $sourceRun = (Get-Content -Raw -LiteralPath $scan | ConvertFrom-Json).run.run_id
    if ($null -eq $sourceRun) {
        throw 'Source fixture scan did not produce a run ID'
    }

    $report = Join-Path $temporaryRoot 'report.json'
    & cargo run --quiet -p codehelion-cli -- artifact analyze $dll --input-format pe-coff --format json --build-variant $variant --source-run $sourceRun --debug-file $pdb --db $database --output $report
    if ($LASTEXITCODE -ne 0) {
        throw "PE/PDB artifact analysis failed with exit code $LASTEXITCODE"
    }

    Assert-Match -Path $report -Pattern '"format": "pe-coff"' -Description 'PE/COFF format'
    Assert-Match -Path $report -Pattern '"name": "duplicate_left"' -Description 'first exported symbol'
    Assert-Match -Path $report -Pattern '"name": "duplicate_right"' -Description 'second exported symbol'
    Assert-Match -Path $report -Pattern '"source_mappings": [1-9]' -Description 'PDB source mappings'
    Assert-Match -Path $report -Pattern '"source_mapping": true' -Description 'PDB source-mapping capability'
    $reportJson = Get-Content -Raw -LiteralPath $report | ConvertFrom-Json
    if ($null -eq $reportJson.correlation) {
        throw 'PE/PDB analysis did not retain the explicit source-run correlation'
    }
    if ($reportJson.correlation.mappings -lt 2) {
        throw "Expected PDB correlation to retain both exported functions, got $($reportJson.correlation.mappings) mappings"
    }
    if ($reportJson.correlation.mapped_symbols -lt 2) {
        throw "Expected PDB correlation to map both exported symbols, got $($reportJson.correlation.mapped_symbols)"
    }

    & cargo run --quiet -p codehelion-cli -- artifact analyze $dll --input-format pe-coff --format json --build-variant $variant --source-run $sourceRun --debug-file $mismatchPdb --db $database
    if ($LASTEXITCODE -eq 0) {
        throw 'A PDB with a different CodeView identity was accepted'
    }

    Write-Output 'PE/PDB artifact fixture end-to-end verification passed'
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
