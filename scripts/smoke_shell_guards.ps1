$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot

function Expect-Failure([string]$Expected, [scriptblock]$Action) {
    $output = ""
    $status = 0
    $global:LASTEXITCODE = 0

    try {
        $output = (& $Action 2>&1 | Out-String)
        $status = $LASTEXITCODE
    }
    catch {
        $output = ($_ | Out-String)
        $status = if ($LASTEXITCODE -ne 0) { $LASTEXITCODE } else { 1 }
    }

    if ($status -eq 0) {
        throw "[smoke] command unexpectedly succeeded."
    }
    if ($output -notlike "*$Expected*") {
        throw "[smoke] command failed without expected diagnostic: $output"
    }

    $global:LASTEXITCODE = 0
}

Write-Host "[smoke] validating PowerShell flag guards"
Expect-Failure "Missing value for --mode" { & pwsh -NoLogo -NoProfile -File (Join-Path $root "scripts\install_scanners.ps1") --mode }
Expect-Failure "Missing value for --mode" { & pwsh -NoLogo -NoProfile -File (Join-Path $root "scripts\install_scanners.ps1") --mode --apply }
Expect-Failure "Missing value for --engine" { & pwsh -NoLogo -NoProfile -File (Join-Path $root "scripts\build_scanner_image.ps1") --engine }
Expect-Failure "Missing value for --engine" { & pwsh -NoLogo -NoProfile -File (Join-Path $root "scripts\build_scanner_image.ps1") --engine --push }
Expect-Failure "Missing value for --image" { & pwsh -NoLogo -NoProfile -File (Join-Path $root "scripts\build_scanner_image.ps1") --image }

Write-Host "[smoke] PowerShell shell guard smoke flow completed"
$global:LASTEXITCODE = 0
