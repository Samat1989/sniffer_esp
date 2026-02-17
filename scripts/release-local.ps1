param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^v[0-9]+(\.[0-9]+){1,3}([\-+][0-9A-Za-z\.\-]+)?$")]
    [string]$Tag,

    [string]$ExportScript = "C:\Espressif\frameworks\esp-idf-v5.5\export.ps1",

    [switch]$FullClean,
    [switch]$Push,
    [switch]$PublishRelease,
    [string]$Repo = "",
    [string]$Token = $env:GITHUB_TOKEN
)

$ErrorActionPreference = "Stop"

function Invoke-Step([string]$Message, [scriptblock]$Action) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
    & $Action
}

function Assert-Tool([string]$ToolName) {
    if (-not (Get-Command $ToolName -ErrorAction SilentlyContinue)) {
        throw "Required tool not found in PATH: $ToolName"
    }
}

function Get-EnvValueFromFile([string]$FilePath, [string]$Key) {
    if (-not (Test-Path -LiteralPath $FilePath)) {
        return $null
    }

    foreach ($line in Get-Content -LiteralPath $FilePath) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#")) {
            continue
        }
        $parts = $trimmed -split "=", 2
        if ($parts.Count -ne 2) {
            continue
        }
        if ($parts[0].Trim() -ne $Key) {
            continue
        }
        return $parts[1].Trim().Trim("'`"")
    }
    return $null
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repoRoot

if (-not $Token) {
    $envFile = Join-Path $repoRoot ".env.local"
    $Token = Get-EnvValueFromFile -FilePath $envFile -Key "GITHUB_TOKEN"
}

Invoke-Step "Checking prerequisites" {
    Assert-Tool "git"
    if (-not (Test-Path -LiteralPath $ExportScript)) {
        throw "ESP-IDF export script not found: $ExportScript"
    }
}

Invoke-Step "Checking repository state" {
    $status = git status --porcelain
    if ($LASTEXITCODE -ne 0) {
        throw "git status failed"
    }
    if ($status) {
        throw "Working tree is not clean. Commit or stash changes before release."
    }
}

Invoke-Step "Activating ESP-IDF environment" {
    & $ExportScript
}

Invoke-Step "Checking ESP-IDF tools" {
    Assert-Tool "idf.py"
}

if ($FullClean) {
    Invoke-Step "Running fullclean" {
        idf.py fullclean
    }
}

Invoke-Step "Configuring build for release tag $Tag" {
    # Force PROJECT_VER to use target tag in local release flow.
    $env:GITHUB_REF_TYPE = "tag"
    $env:GITHUB_REF_NAME = $Tag
    idf.py reconfigure
}

Invoke-Step "Building firmware" {
    idf.py build
}

$releaseDir = Join-Path $repoRoot "firmware\$Tag"
$latestDir = Join-Path $repoRoot "firmware\latest"

Invoke-Step "Preparing firmware folders" {
    New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null
    New-Item -ItemType Directory -Force -Path $latestDir | Out-Null
}

$artifacts = @(
    @{ Src = "build\sniffer_esp.bin"; Dst = "sniffer_esp.bin" },
    @{ Src = "build\bootloader\bootloader.bin"; Dst = "bootloader.bin" },
    @{ Src = "build\partition_table\partition-table.bin"; Dst = "partition-table.bin" },
    @{ Src = "build\ota_data_initial.bin"; Dst = "ota_data_initial.bin" }
)

Invoke-Step "Copying firmware artifacts" {
    foreach ($a in $artifacts) {
        if (-not (Test-Path -LiteralPath $a.Src)) {
            throw "Build artifact not found: $($a.Src)"
        }
        Copy-Item -LiteralPath $a.Src -Destination (Join-Path $releaseDir $a.Dst) -Force
        Copy-Item -LiteralPath $a.Src -Destination (Join-Path $latestDir $a.Dst) -Force
    }
}

Invoke-Step "Generating checksums" {
    $shaFile = Join-Path $releaseDir "SHA256SUMS.txt"
    if (Test-Path -LiteralPath $shaFile) {
        Remove-Item -LiteralPath $shaFile -Force
    }
    foreach ($a in $artifacts) {
        $filePath = Join-Path $releaseDir $a.Dst
        $hash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLower()
        Add-Content -LiteralPath $shaFile -Value "$hash  $($a.Dst)"
    }
    Copy-Item -LiteralPath $shaFile -Destination (Join-Path $latestDir "SHA256SUMS.txt") -Force
}

Invoke-Step "Committing artifacts and creating tag" {
    git add firmware
    git commit -m "Release ${Tag}: publish local firmware artifacts"

    $existingTag = git tag --list $Tag
    if ($existingTag) {
        throw "Tag already exists locally: $Tag"
    }
    git tag -a $Tag -m "Release $Tag"
}

if ($Push) {
    Invoke-Step "Pushing commit and tag" {
        git push origin main
        git push origin $Tag
    }
} else {
    Write-Host "`nRelease prepared locally. To push now run:" -ForegroundColor Yellow
    Write-Host "git push origin main"
    Write-Host "git push origin $Tag"
}

if ($PublishRelease) {
    Invoke-Step "Publishing GitHub release assets (no Actions)" {
        $publishScript = Join-Path $PSScriptRoot "publish-github-release.ps1"
        if (-not (Test-Path -LiteralPath $publishScript)) {
            throw "Script not found: $publishScript"
        }
        & $publishScript -Tag $Tag -Repo $Repo -Token $Token
    }
}

Write-Host "`nDone: firmware artifacts are in firmware\$Tag and firmware\latest" -ForegroundColor Green
