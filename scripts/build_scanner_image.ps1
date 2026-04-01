$ErrorActionPreference = "Stop"

function Show-Usage {
    @"
Usage: pwsh scripts/build_scanner_image.ps1 [--engine docker|podman|auto] [--image <tag>] [--push]

Builds the pinned scanner bundle image used by IronSentinel container isolation.
"@
}

$RootDir = Split-Path -Parent $PSScriptRoot
$Containerfile = if ($env:APPSEC_CONTAINERFILE_PATH) { $env:APPSEC_CONTAINERFILE_PATH } else { Join-Path $RootDir "deploy\scanner-bundle.Containerfile" }
$Image = if ($env:AEGIS_CONTAINER_IMAGE) { $env:AEGIS_CONTAINER_IMAGE } else { "ghcr.io/batu3384/ironsentinel-scanner-bundle:latest" }
$Engine = if ($env:AEGIS_CONTAINER_ENGINE) { $env:AEGIS_CONTAINER_ENGINE } else { "auto" }
$Push = $false

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
        "--engine" {
            $index++
            $Engine = Require-ArgValue "--engine" $index
        }
        "--image" {
            $index++
            $Image = Require-ArgValue "--image" $index
        }
        "--push" {
            $Push = $true
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

function Resolve-Engine([string]$Preferred) {
    if ($Preferred -eq "docker" -or $Preferred -eq "podman") {
        $command = Get-Command $Preferred -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return $command.Source
        }
        throw "Requested container engine not found: $Preferred"
    }

    foreach ($candidate in @("podman", "docker")) {
        $command = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return $command.Source
        }
    }
    throw "No supported container engine found. Install docker or podman."
}

if (-not (Test-Path -LiteralPath $Containerfile)) {
    throw "Containerfile not found: $Containerfile"
}

$EnginePath = Resolve-Engine $Engine

Write-Host "Building scanner image with $(Split-Path -Leaf $EnginePath)"
Write-Host "Containerfile: $Containerfile"
Write-Host "Image: $Image"

& $EnginePath build `
    -f $Containerfile `
    -t $Image `
    $RootDir

if ($Push) {
    Write-Host "Pushing $Image"
    & $EnginePath push $Image
}
