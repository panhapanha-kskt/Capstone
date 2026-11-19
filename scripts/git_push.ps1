# One-command commit + push for this repo (run from anywhere, in PowerShell):
#   powershell -ExecutionPolicy Bypass -File scripts\git_push.ps1 "your message"
# Commits only files git already tracks plus docs/, refuses data/processed, runs/, models/ and logs,
# then pushes the current branch to GitHub.
param([string]$Message = "Update docs")
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$branch = (git rev-parse --abbrev-ref HEAD).Trim()
Write-Host "Branch: $branch"

git add -u            # changes to files git already tracks
git add docs/         # new doc files

# Never commit these (project rules)
$blocked = git diff --cached --name-only | Where-Object {
  $_ -match '^(data/processed/|data/raw/|runs/|models/|logs/)' -or $_ -match '\.(pcap|log)$'
}
if ($blocked) {
  git reset -q -- $blocked
  Write-Host "Left out (not allowed in git):" -ForegroundColor Yellow
  $blocked | ForEach-Object { Write-Host "  $_" }
}

$staged = git diff --cached --name-only
if (-not $staged) { Write-Host "Nothing to commit."; exit 0 }
Write-Host "Committing:"; $staged | ForEach-Object { Write-Host "  $_" }

git commit -m $Message
git push -u origin $branch
Write-Host "Pushed to origin/$branch" -ForegroundColor Green
