param(
    [string]$Tag = "",

    [string]$Repo = "",
    [string]$Token = $env:GITHUB_TOKEN
)

$ErrorActionPreference = "Stop"

$TagPattern = "^v[0-9]+(\.[0-9]+){1,3}([\-+][0-9A-Za-z\.\-]+)?$"

function Normalize-Token([string]$Value) {
    if ($null -eq $Value) {
        return $null
    }
    # Remove CR/LF and other control chars that break HTTP header values.
    $clean = ($Value -replace "[\x00-\x1F\x7F]", "").Trim().Trim("'`"")
    if ($clean -eq "") {
        return $null
    }
    return $clean
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

function Get-RepoFromGitRemote {
    $url = (git remote get-url origin).Trim()
    if (-not $url) {
        throw "Cannot detect origin remote URL."
    }

    if ($url -match "^git@github\.com:(.+)\.git$") {
        return $Matches[1]
    }
    if ($url -match "^https://github\.com/(.+)\.git$") {
        return $Matches[1]
    }
    if ($url -match "^https://github\.com/(.+)$") {
        return $Matches[1]
    }

    throw "Unsupported origin remote URL: $url"
}

function Resolve-DefaultTag {
    $headTags = @(git tag --points-at HEAD --list "v*" 2>$null)
    if ($headTags.Count -gt 0) {
        return $headTags[0].Trim()
    }

    $allTags = @(git tag --sort=-v:refname --list "v*" 2>$null)
    foreach ($t in $allTags) {
        $trimmed = $t.Trim()
        if ($trimmed -match $TagPattern) {
            return $trimmed
        }
    }

    throw "Cannot auto-detect release tag. Pass -Tag explicitly (example: -Tag v1.0.29)."
}

function Invoke-GhApi([string]$Method, [string]$Uri, $Body = $null, [string]$ContentType = "application/json") {
    $headers = @{
        Authorization = "Bearer $Token"
        Accept        = "application/vnd.github+json"
        "X-GitHub-Api-Version" = "2022-11-28"
    }

    if ($null -eq $Body) {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
    }

    if ($ContentType -eq "application/json") {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body ($Body | ConvertTo-Json -Depth 10) -ContentType $ContentType
    }

    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -InFile $Body -ContentType $ContentType
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
if ($Token) {
    $Token = Normalize-Token $Token
}

if (-not $Token) {
    $envFile = Join-Path $repoRoot ".env.local"
    $Token = Get-EnvValueFromFile -FilePath $envFile -Key "GITHUB_TOKEN"
    $Token = Normalize-Token $Token
}

if (-not $Token) {
    throw "GITHUB_TOKEN is empty. Set env var, pass -Token, or define it in .env.local."
}

if (-not $Repo) {
    $Repo = Get-RepoFromGitRemote
}

if (-not $Tag) {
    $Tag = Resolve-DefaultTag
    Write-Host "Auto-detected tag: $Tag"
}

if ($Tag -notmatch $TagPattern) {
    throw "Invalid tag format: $Tag. Expected vX.Y.Z (for example: v1.0.29)."
}

$releaseDir = Join-Path $repoRoot "firmware\$Tag"
if (-not (Test-Path -LiteralPath $releaseDir)) {
    throw "Release folder not found: $releaseDir. Run release-local.ps1 first."
}

$assets = Get-ChildItem -LiteralPath $releaseDir -File | Where-Object { $_.Name -match "\.bin$|^SHA256SUMS\.txt$" }
if ($assets.Count -eq 0) {
    throw "No release assets found in $releaseDir"
}

$apiBase = "https://api.github.com/repos/$Repo"

try {
    $release = Invoke-GhApi -Method "GET" -Uri "$apiBase/releases/tags/$Tag"
    Write-Host "Using existing release for tag $Tag"
} catch {
    $body = @{
        tag_name   = $Tag
        name       = $Tag
        draft      = $false
        prerelease = $false
        generate_release_notes = $true
    }
    $release = Invoke-GhApi -Method "POST" -Uri "$apiBase/releases" -Body $body
    Write-Host "Created release $Tag"
}

$uploadUrl = ($release.upload_url -replace "\{\?name,label\}", "")

foreach ($file in $assets) {
    $assetName = $file.Name

    $existing = $release.assets | Where-Object { $_.name -eq $assetName }
    if ($existing) {
        Invoke-GhApi -Method "DELETE" -Uri "$apiBase/releases/assets/$($existing.id)" | Out-Null
        Write-Host "Deleted existing asset: $assetName"
    }

    $encoded = [System.Uri]::EscapeDataString($assetName)
    $assetUri = "${uploadUrl}?name=$encoded"
    Invoke-GhApi -Method "POST" -Uri $assetUri -Body $file.FullName -ContentType "application/octet-stream" | Out-Null
    Write-Host "Uploaded: $assetName"
}

Write-Host "Release published: $($release.html_url)"
