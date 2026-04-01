$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tmpDir | Out-Null

try {
    $env:APPSEC_DATA_DIR = Join-Path $tmpDir "data"
    $env:APPSEC_OUTPUT_DIR = Join-Path $tmpDir "output"
    $env:APPSEC_MIRROR_DIR = Join-Path $tmpDir "mirrors"
    $env:AEGIS_TOOLS_DIR = Join-Path $tmpDir "tools\bin"

    Write-Host "[smoke] isolated runtime root: $tmpDir"
    Write-Host "[smoke] running core setup"
    Push-Location $root
    try {
        go run ./cmd/ironsentinel setup --target auto --coverage core --mirror=false --lang en *> (Join-Path $tmpDir "setup.out")
    }
    finally {
        Pop-Location
    }

    Write-Host "[smoke] running safe-mode runtime doctor"
    $doctorOut = Join-Path $tmpDir "doctor.out"
    Push-Location $root
    try {
        $previous = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        go run ./cmd/ironsentinel runtime doctor --mode safe --lang en *> $doctorOut
        $doctorStatus = $LASTEXITCODE
        $ErrorActionPreference = $previous
    }
    finally {
        Pop-Location
    }

    if ($doctorStatus -ne 0) {
        $content = Get-Content $doctorOut -Raw
        if ($content -notmatch "Runtime bundle doctor|runtime doctor failed|Missing tools") {
            Write-Error "[smoke] runtime doctor failed without expected diagnostics`n$content"
        }
        Write-Host "[smoke] runtime doctor reported an expected readiness failure on this machine"
        $global:LASTEXITCODE = 0
    }
    else {
        Write-Host "[smoke] runtime doctor passed"
        $global:LASTEXITCODE = 0
    }

    Write-Host "[smoke] smoke setup/doctor flow completed"
}
finally {
    if (Test-Path $tmpDir) {
        Remove-Item -Recurse -Force $tmpDir
    }
}
