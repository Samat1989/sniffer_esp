param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^v[0-9]+(\.[0-9]+){1,3}([\-+][0-9A-Za-z\.\-]+)?$")]
    [string]$Tag,

    [string]$Repo = "",
    [string]$Token = $env:GITHUB_TOKEN
)

$ErrorActionPreference = "Stop"

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

if (-not $Token) {
    throw "GITHUB_TOKEN is empty. Set it before running this script."
}

if (-not $Repo) {
    $Repo = Get-RepoFromGitRemote
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
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
