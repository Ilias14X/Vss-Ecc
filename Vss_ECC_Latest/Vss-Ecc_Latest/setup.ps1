# Windows (PowerShell) : crée .venv, installe les dépendances, lance les tests, ouvre VS Code
Set-Location $PSScriptRoot
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -q -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q tests
if (Get-Command code -ErrorAction SilentlyContinue) { code . } else { Write-Host "Ouvre ce dossier dans VS Code (File > Open Folder)." }
