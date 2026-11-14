# Сборка установщика DeepSec Agent. Запускать на Windows из папки проекта:
#   powershell -ExecutionPolicy Bypass -File packaging\build.ps1
# Нужны Rust (rustup, toolchain stable-msvc) и Inno Setup 6 (поставится через choco, если его нет).
# Результат: dist\DeepSecSetup-<версия>.exe
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what завершилось с кодом $LASTEXITCODE" } }

# Агент — один exe на Rust (agent-rs/). Сборка заодно рисует иконку и картинку мастера в build\
cargo build --release --locked --manifest-path agent-rs\Cargo.toml
Check 'cargo build'
$exe = 'agent-rs\target\release\DeepSecAgent.exe'
$version = (& $exe version).Trim()
Check 'DeepSecAgent.exe version'

$iscc = (Get-Command iscc.exe -ErrorAction SilentlyContinue).Source
if (-not $iscc) { $iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" }
if (-not (Test-Path $iscc)) {
    choco install innosetup -y --no-progress
    Check 'choco install innosetup'
}
& $iscc "/DAppVersion=$version" packaging\deepsec.iss
Check 'Inno Setup'
Write-Host "Готово: dist\DeepSecSetup-$version.exe"
