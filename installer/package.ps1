# Сборка установщика «Просто Подпись».
#
# Собирает приложение и CLI, кладёт файлы в payload и упаковывает установщик.

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$app = Join-Path $root "app"
$cli = Join-Path $root "cli"
$payload = Join-Path $PSScriptRoot "payload"

Write-Host "1/4 Подпись приложения…"
Push-Location $app
cargo build --release --message-format short
Pop-Location

Write-Host "2/4 Подпись CLI…"
Push-Location $cli
cargo build --release --message-format short
Copy-Item (Join-Path $cli "target\release\Podpis-cli.exe") (Join-Path $app "target\release\Podpis-cli.exe") -Force
Pop-Location

Write-Host "3/4 Подготовка файлов установки…"
New-Item -ItemType Directory -Force -Path $payload | Out-Null
Copy-Item (Join-Path $app "target\release\Podpis.exe") (Join-Path $payload "Podpis.exe") -Force
Copy-Item (Join-Path $app "target\release\Podpis-cli.exe") (Join-Path $payload "Podpis-cli.exe") -Force
$pdf = Get-ChildItem (Join-Path $app "docs") -Filter *.pdf | Select-Object -First 1
Copy-Item $pdf.FullName (Join-Path $payload "manual.pdf") -Force
Copy-Item (Join-Path $app "assets\app_icon.ico") (Join-Path $PSScriptRoot "assets\setup.ico") -Force

Write-Host "4/4 Сборка установщика…"
Push-Location $PSScriptRoot
cargo build --release --message-format short
Pop-Location

$setup = Join-Path $PSScriptRoot "target\release\ProstoPodpis-Setup.exe"
Copy-Item $setup (Join-Path $app "target\release\ProstoPodpis-Setup.exe") -Force
Write-Host "Готово: $setup"
