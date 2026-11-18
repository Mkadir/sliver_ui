# Offline Windows entrypoint: runs the Linux setup.sh inside WSL.
# The packed binaries are Linux ELF — use WSL2 (Ubuntu recommended).
#
# Usage (PowerShell, from the extracted bundle folder):
#   powershell -ExecutionPolicy Bypass -File .\setup.ps1
#   .\setup.ps1 -Addr 0.0.0.0:8080 -User admin -Pass 'yourpass'
#
# Then open http://127.0.0.1:8080/ in Windows browser (WSL forwards localhost).

param(
  [string]$Addr = "127.0.0.1:8080",
  [string]$User = "admin",
  [string]$Pass = "",
  [switch]$NoAuth,
  [switch]$ReplaceServer,
  [switch]$SkipSystemd,
  [switch]$NoStart
)

$ErrorActionPreference = "Stop"
$BundleDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Require-Wsl {
  $wsl = Get-Command wsl -ErrorAction SilentlyContinue
  if (-not $wsl) {
    Write-Host "[x] WSL not found. Install WSL2 + Ubuntu, then re-run." -ForegroundColor Red
    Write-Host "    wsl --install -d Ubuntu"
    exit 1
  }
}

Require-Wsl

$argsList = @("--addr", $Addr, "--user", $User)
if ($Pass -ne "") { $argsList += @("--pass", $Pass) }
if ($NoAuth) { $argsList += "--no-auth" }
if ($ReplaceServer) { $argsList += "--replace-server" }
if ($SkipSystemd) { $argsList += "--skip-systemd" }
if ($NoStart) { $argsList += "--no-start" }

# Convert Windows path to WSL path and run setup.sh
$wslDir = (wsl -e wslpath -a $BundleDir).Trim()
$quoted = ($argsList | ForEach-Object {
  if ($_ -match '[\s"]') { "'" + ($_ -replace "'", "'\''") + "'" } else { $_ }
}) -join " "

Write-Host "[*] Running offline setup inside WSL…" -ForegroundColor Cyan
wsl -e bash -lc "cd '$wslDir' && bash ./setup.sh $quoted"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$port = ($Addr -split ":")[-1]
Write-Host ""
Write-Host "[+] Open in Windows: http://127.0.0.1:$port/" -ForegroundColor Green
Write-Host "    Login credentials were printed by setup.sh above."
