$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot

function Expect-Failure([string]$Expected, [scriptblock]$Action) {
    try {
        & $Action 2>&1 | Out-String | Out-Null
        throw "Command unexpectedly succeeded."
    }
    catch {
        $message = $_.Exception.Message
        if ($message -notlike "*$Expected*") {
            throw "[smoke] command failed without expected diagnostic: $message"
        }
    }
}

Write-Host "[smoke] validating PowerShell flag guards"
Expect-Failure "Missing value for --mode" { & pwsh -NoLogo -NoProfile -File (Join-Path $root "scripts\install_scanners.ps1") --mode }
Expect-Failure "Missing value for --mode" { & pwsh -NoLogo -NoProfile -File (Join-Path $root "scripts\install_scanners.ps1") --mode --apply }
Expect-Failure "Missing value for --engine" { & pwsh -NoLogo -NoProfile -File (Join-Path $root "scripts\build_scanner_image.ps1") --engine }
Expect-Failure "Missing value for --engine" { & pwsh -NoLogo -NoProfile -File (Join-Path $root "scripts\build_scanner_image.ps1") --engine --push }
Expect-Failure "Missing value for --image" { & pwsh -NoLogo -NoProfile -File (Join-Path $root "scripts\build_scanner_image.ps1") --image }

Write-Host "[smoke] PowerShell shell guard smoke flow completed"
