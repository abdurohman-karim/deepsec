# Сборка установщика DeepSec Agent. Запускать на Windows из папки проекта:
#   powershell -ExecutionPolicy Bypass -File packaging\build.ps1
# Результат: dist\DeepSecSetup-<версия>.exe
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what завершилось с кодом $LASTEXITCODE" } }

python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements-agent.txt pyinstaller
Check 'pip install'
$version = (python -c "import deepsec; print(deepsec.__version__)").Trim()

# onedir, а не onefile: файлы лежат в Program Files (писать туда может только администратор),
# а не распаковываются при каждом запуске во временную папку.
python -m PyInstaller --noconfirm --clean --console --name DeepSecAgent `
    --hidden-import deepsec.agent --hidden-import deepsec.setup_win `
    --distpath dist --workpath build --specpath build packaging\agent_entry.py
Check 'PyInstaller'

# Сборка должна запускаться и видеть все модули агента
& dist\DeepSecAgent\DeepSecAgent.exe version
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
