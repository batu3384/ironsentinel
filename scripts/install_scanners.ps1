$ErrorActionPreference = "Stop"

function Show-Usage {
    @"
Usage: pwsh scripts/install_scanners.ps1 [--mode safe|deep|active|full] [--apply]

Without --apply, the script prints the pinned install plan.
With --apply, it installs Windows-friendly local wrappers and binaries into the IronSentinel managed tools directory.
"@
}

$Mode = "safe"
$Apply = $false

function Require-ArgValue([string]$Flag, [int]$Index) {
    if ($Index -ge $args.Count) {
        throw "Missing value for $Flag"
    }

    $value = $args[$Index]
    if ([string]::IsNullOrWhiteSpace($value) -or $value.StartsWith("--")) {
        throw "Missing value for $Flag"
    }

    return $value
}

for ($index = 0; $index -lt $args.Count; $index++) {
    switch ($args[$index]) {
        "--mode" {
            $index++
            $Mode = Require-ArgValue "--mode" $index
        }
        "--apply" {
            $Apply = $true
        }
        "--help" {
            Show-Usage
            exit 0
        }
        "-h" {
            Show-Usage
            exit 0
        }
        default {
            throw "Unknown argument: $($args[$index])"
        }
    }
}

$RootDir = Split-Path -Parent $PSScriptRoot
$ToolsDir = if ($env:IRONSENTINEL_TOOLS_DIR) { $env:IRONSENTINEL_TOOLS_DIR } else { Join-Path $RootDir "runtime\tools\bin" }
$ToolsRoot = Split-Path -Parent $ToolsDir
$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ironsentinel-installer"

function Ensure-Directory([string]$Path) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
}

function Get-ArchTag {
    switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()) {
        "arm64" { return "arm64" }
        "x64" { return "amd64" }
        default { return "amd64" }
    }
}

function Require-Command([string]$Name) {
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        throw "Required command not found: $Name"
    }
    return $command.Source
}

function Resolve-Python {
    foreach ($candidate in @("py", "python")) {
        $command = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return $command.Source
        }
    }
    throw "Python launcher not found. Install Python 3 first."
}

function Resolve-Node {
    foreach ($candidate in @("node", "node.exe")) {
        $command = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return $command.Source
        }
    }
    throw "Node.js not found. Install Node.js first."
}

function Resolve-Npm {
    foreach ($candidate in @("npm", "npm.cmd")) {
        $command = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return $command.Source
        }
    }
    throw "npm not found. Install Node.js first."
}

function Invoke-Download([string]$Url, [string]$Destination) {
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Destination
}

function New-TempWorkDir {
    Ensure-Directory $TempRoot
    $workDir = Join-Path $TempRoot ([guid]::NewGuid().ToString("N"))
    Ensure-Directory $workDir
    return $workDir
}

function Write-CmdWrapper([string]$Name, [string]$TargetCommand) {
    Ensure-Directory $ToolsDir
    $wrapperPath = Join-Path $ToolsDir "$Name.cmd"
    $content = "@echo off`r`n$TargetCommand %*`r`n"
    Set-Content -Path $wrapperPath -Value $content -NoNewline
}

function Get-PythonScriptsDir([string]$PythonPath) {
    $userBase = & $PythonPath -c "import site; print(site.USER_BASE)"
    if ([string]::IsNullOrWhiteSpace($userBase)) {
        throw "Could not resolve Python user base directory."
    }
    return (Join-Path $userBase.Trim() "Scripts")
}

function Find-FirstExisting([string[]]$Candidates) {
    foreach ($candidate in $Candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }
    return $null
}

function Install-PythonTool([string]$Package, [string]$Version, [string]$CommandName) {
    $python = Resolve-Python
    & $python -m pip install --user --disable-pip-version-check --upgrade "$Package==$Version"

    $scriptsDir = Get-PythonScriptsDir $python
    $scriptPath = Find-FirstExisting @(
        (Join-Path $scriptsDir "$CommandName.exe"),
        (Join-Path $scriptsDir "$CommandName-script.py"),
        (Join-Path $scriptsDir $CommandName)
    )

    if ($null -eq $scriptPath) {
        Write-CmdWrapper $CommandName ('"{0}" -m {1}' -f $python, $Package)
        return
    }

    if ($scriptPath.EndsWith(".py")) {
        Write-CmdWrapper $CommandName ('"{0}" "{1}"' -f $python, $scriptPath)
        return
    }

    Write-CmdWrapper $CommandName ('"{0}"' -f $scriptPath)
}

function Install-GoTool([string]$Module, [string]$Version) {
    $goPath = Require-Command "go"
    Ensure-Directory $ToolsDir
    $previous = $env:GOBIN
    $env:GOBIN = $ToolsDir
    try {
        & $goPath install "$Module@$Version"
    }
    finally {
        $env:GOBIN = $previous
    }
}

function Install-ZipBinary([string]$Url, [string]$BinaryName, [string]$OutputName) {
    $workDir = New-TempWorkDir
    try {
        $archive = Join-Path $workDir "asset.zip"
        Invoke-Download $Url $archive
        Expand-Archive -LiteralPath $archive -DestinationPath $workDir -Force

        $binary = Get-ChildItem -Path $workDir -Recurse -File | Where-Object { $_.Name -ieq $BinaryName } | Select-Object -First 1
        if ($null -eq $binary) {
            throw "Binary $BinaryName not found in archive: $Url"
        }

        Ensure-Directory $ToolsDir
        Copy-Item -LiteralPath $binary.FullName -Destination (Join-Path $ToolsDir $OutputName) -Force
    }
    finally {
        if (Test-Path -LiteralPath $workDir) {
            Remove-Item -LiteralPath $workDir -Recurse -Force
        }
    }
}

function Install-DirectBinary([string]$Url, [string]$OutputName) {
    Ensure-Directory $ToolsDir
    Invoke-Download $Url (Join-Path $ToolsDir $OutputName)
}

function Install-CodeQLBundle {
    $workDir = New-TempWorkDir
    try {
        $archive = Join-Path $workDir "codeql-bundle-win64.tar.gz"
        Invoke-Download "https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.23.3/codeql-bundle-win64.tar.gz" $archive

        $null = Require-Command "tar"
        & tar -xzf $archive -C $workDir

        $bundleDir = Get-ChildItem -Path $workDir -Directory | Where-Object { $_.Name -match "^codeql" } | Select-Object -First 1
        if ($null -eq $bundleDir) {
            throw "CodeQL bundle directory not found after extraction."
        }

        $targetRoot = Join-Path $ToolsRoot "codeql"
        if (Test-Path -LiteralPath $targetRoot) {
            Remove-Item -LiteralPath $targetRoot -Recurse -Force
        }
        Copy-Item -LiteralPath $bundleDir.FullName -Destination $targetRoot -Recurse -Force
        Write-CmdWrapper "codeql" ('"{0}"' -f (Join-Path $targetRoot "codeql.exe"))
    }
    finally {
        if (Test-Path -LiteralPath $workDir) {
            Remove-Item -LiteralPath $workDir -Recurse -Force
        }
    }
}

function Install-Knip {
    $npm = Resolve-Npm
    $npmRoot = Join-Path $ToolsRoot "npm"
    Ensure-Directory $npmRoot
    & $npm install --prefix $npmRoot "knip@5.70.1"
    Write-CmdWrapper "knip" ('"{0}" exec --prefix "{1}" knip --' -f $npm, $npmRoot)
}

function Install-Note([string]$Message) {
    Write-Warning $Message
}

function New-Step([string]$Description, [scriptblock]$Action) {
    return [pscustomobject]@{
        Description = $Description
        Action      = $Action
    }
}

function Invoke-Steps([string]$Title, [object[]]$Steps, [bool]$ShouldApply) {
    Write-Host $Title
    foreach ($step in $Steps) {
        if ($ShouldApply) {
            Write-Host "  -> $($step.Description)"
            & $step.Action
        }
        else {
            Write-Host "  $($step.Description)"
        }
    }
    Write-Host ""
}

$arch = Get-ArchTag
Ensure-Directory $ToolsDir
Ensure-Directory $ToolsRoot

$safeSteps = @(
    New-Step 'Install semgrep 1.119.0 into the managed tools directory' { Install-PythonTool "semgrep" "1.119.0" "semgrep" },
    New-Step 'Install checkov 3.2.489 into the managed tools directory' { Install-PythonTool "checkov" "3.2.489" "checkov" },
    New-Step 'Install staticcheck 2025.1.1 into the managed tools directory' { Install-GoTool "honnef.co/go/tools/cmd/staticcheck" "2025.1.1" },
    New-Step 'Install govulncheck 1.1.4 into the managed tools directory' { Install-GoTool "golang.org/x/vuln/cmd/govulncheck" "v1.1.4" },
    New-Step 'Install gitleaks 8.24.2 into the managed tools directory' {
        Install-ZipBinary "https://github.com/gitleaks/gitleaks/releases/download/v8.24.2/gitleaks_8.24.2_windows_x64.zip" "gitleaks.exe" "gitleaks.exe"
    },
    New-Step 'Install trivy 0.69.1 into the managed tools directory' {
        Install-ZipBinary "https://github.com/aquasecurity/trivy/releases/download/v0.69.1/trivy_0.69.1_windows-64bit.zip" "trivy.exe" "trivy.exe"
    },
    New-Step 'Install syft 1.22.0 into the managed tools directory' {
        Install-ZipBinary "https://github.com/anchore/syft/releases/download/v1.22.0/syft_1.22.0_windows_amd64.zip" "syft.exe" "syft.exe"
    },
    New-Step 'Install osv-scanner 2.2.2 into the managed tools directory' {
        Install-DirectBinary "https://github.com/google/osv-scanner/releases/download/v2.2.2/osv-scanner_windows_amd64.exe" "osv-scanner.exe"
    }
)

$deepSteps = @(
    New-Step 'Install CodeQL bundle 2.23.3 into the managed tools directory' { Install-CodeQLBundle },
    New-Step 'Install knip 5.70.1 into the managed tools directory' { Install-Knip },
    New-Step 'Install vulture 2.14 into the managed tools directory' { Install-PythonTool "vulture" "2.14" "vulture" }
)

$activeSteps = @(
    New-Step 'Install nuclei 3.4.10 into the managed tools directory' {
        Install-ZipBinary "https://github.com/projectdiscovery/nuclei/releases/download/v3.4.10/nuclei_3.4.10_windows_amd64.zip" "nuclei.exe" "nuclei.exe"
    },
    New-Step 'Use container isolation for OWASP ZAP on Windows' {
        Install-Note "OWASP ZAP local bootstrap on Windows remains container-first. Use ironsentinel runtime image build and scan --isolation container for active DAST."
    }
)

$steps = @()
switch ($Mode) {
    "safe" {
        $steps += $safeSteps
    }
    "deep" {
        $steps += $safeSteps + $deepSteps
    }
    "active" {
        $steps += $activeSteps
    }
    "full" {
        $steps += $safeSteps + $deepSteps + $activeSteps
    }
    default {
        throw "Unsupported mode: $Mode"
    }
}

Invoke-Steps "Pinned scanner install plan for mode: $Mode on Windows/$arch" $steps $Apply
Write-Host "Managed tools directory: $ToolsDir"
if ($Apply) {
    Write-Host "Installation attempt finished."
}
else {
    Write-Host "Run again with --apply to execute the commands."
}
