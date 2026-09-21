# Build the plugin and copy the bundle into the global opencode plugins directory.
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$DestDir = Join-Path $env:USERPROFILE ".config\opencode\plugins"
$Dest = Join-Path $DestDir "security-guard.js"

Set-Location $RepoRoot
npm run build

New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
Copy-Item -Force (Join-Path $RepoRoot "dist\security-guard.js") $Dest

Write-Host "Installed: $Dest"
Write-Host "Restart opencode to load the new bundle."
