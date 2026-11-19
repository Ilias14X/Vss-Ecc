#!/usr/bin/env bash
# Linux / macOS : crée .venv, installe les dépendances, lance les tests, ouvre VS Code
set -e
cd "$(dirname "$0")"
python3 -m venv .venv
.venv/bin/python -m pip install -q -r requirements.txt
.venv/bin/python -m pytest -q tests
command -v code >/dev/null && code . || echo "Ouvre ce dossier dans VS Code (File > Open Folder)."
