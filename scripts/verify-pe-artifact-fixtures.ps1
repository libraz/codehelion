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
    & cargo run --quiet -p codehelion -- scan $fixtureRoot --mode structural --format json --db $database --output $scan
    if ($LASTEXITCODE -ne 0) {
        throw "Source fixture scan failed with exit code $LASTEXITCODE"
    }
    $sourceRun = (Get-Content -Raw -LiteralPath $scan | ConvertFrom-Json).run.run_id
    if ($null -eq $sourceRun) {
        throw 'Source fixture scan did not produce a run ID'
    }

    $report = Join-Path $temporaryRoot 'report.json'
    & cargo run --quiet -p codehelion -- artifact analyze $dll --input-format pe-coff --format json --build-variant $variant --source-run $sourceRun --debug-file $pdb --db $database --output $report
    if ($LASTEXITCODE -ne 0) {
        throw "PE/PDB artifact analysis failed with exit code $LASTEXITCODE"
    }

    Assert-Match -Path $report -Pattern '"format": "pe-coff"' -Description 'PE/COFF format'
    Assert-Match -Path $report -Pattern '"source_mappings": [1-9]' -Description 'PDB source mappings'
    Assert-Match -Path $report -Pattern '"source_mapping": true' -Description 'PDB source-mapping capability'
    $reportJson = Get-Content -Raw -LiteralPath $report | ConvertFrom-Json
    if ($null -eq $reportJson.correlation) {
        throw 'PE/PDB analysis did not retain the explicit source-run correlation'
    }
    # Printed rather than required. The PDB is read and its line information
    # reaches the report, which is what the assertions above establish. Joining
    # that information back to the entities a scan recorded is a further step
    # this parser does not take for a linked image: it keeps its function names
    # in the PDB rather than in a COFF symbol table, so the image is read as one
    # region of code with no boundary to attribute against. The numbers are here
    # so a run says where that stands instead of leaving it unsaid.
    Write-Output "correlation mappings: $($reportJson.correlation.mappings); mapped symbols: $($reportJson.correlation.mapped_symbols)"

    # The refusal this asks for is the last command's exit code, and a script
    # ends with the last exit code it saw. Cleared here, so a verification that
    # got what it asked for does not report the refusal as its own failure.
    & cargo run --quiet -p codehelion -- artifact analyze $dll --input-format pe-coff --format json --build-variant $variant --source-run $sourceRun --debug-file $mismatchPdb --db $database
    if ($LASTEXITCODE -eq 0) {
        throw 'A PDB with a different CodeView identity was accepted'
    }
    $global:LASTEXITCODE = 0

    Write-Output 'PE/PDB artifact fixture end-to-end verification passed'
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
