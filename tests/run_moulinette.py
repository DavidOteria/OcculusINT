import subprocess
import sys
import os
from pathlib import Path

# Couleurs terminal (fonctionnent dans beaucoup de consoles modernes)
RED = "\033[91m"
GREEN = "\033[92m"
NC = "\033[0m"

# Détection du bon interpréteur Python (venv ou système)
PYTHON = sys.executable

# Fichiers et répertoires
DATA_DIR = Path("tests/moulinette_data")
LOG_DIR = Path("tests/moulinette_logs")
INPUT_FILE = DATA_DIR / "moulinette_test.csv"

# API Shodan passée en argument
SHODAN_KEY = sys.argv[1] if len(sys.argv) > 1 else None

if not SHODAN_KEY:
    print(f"{RED}[!] Usage: python run_moulinette.py <SHODAN_API_KEY>{NC}")
    sys.exit(1)

# Créer le dossier de logs et copier le CSV de base
LOG_DIR.mkdir(parents=True, exist_ok=True)
tmp_file = LOG_DIR / "input.csv"
tmp_file.write_text(INPUT_FILE.read_text(), encoding="utf-8")

def run_step(label: str, cmd: list):
    log_path = LOG_DIR / f"{label}.log"
    print(f"\n[~] Step: {label}")
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=True,
            encoding="utf-8",   # ← ici !
            errors="replace"    # ← ici aussi : remplace caractères invalides
        )
        log_path.write_text(result.stdout, encoding="utf-8")
        print(f"{GREEN}[✔] {label} passed{NC}")
    except subprocess.CalledProcessError as e:
        log_path.write_text(e.stdout or "", encoding="utf-8")
        print(f"{RED}[✘] {label} failed — see {log_path}{NC}")

def path(step: str):
    """Construit un chemin intermédiaire basé sur input.csv"""
    return str(tmp_file).replace(".csv", f"_{step}.csv")

# Pipeline complet
run_step("resolve",[PYTHON, "main.py", "resolve", str(tmp_file)])
run_step("passive-vuln",[PYTHON, "main.py", "passive-vuln", path("resolved"), SHODAN_KEY])
run_step("enrich",[PYTHON, "main.py", "enrich", path("resolved_vuln")])
run_step("filter", [
    PYTHON, "main.py", "filter", path("resolved_vuln_enriched"),
    "bnp", "bnpparibas", "banque", "login", "auth", "ssl", "vpn",
    "cloud", "azure", "ovh", "aws", "finance", "mail", "smtp",
    "api", "client", "admin", "support", "zimbra", "sandbox",
    "192.168", "10.0", "test", "prod", "staging", "telechargement",
    "gateway", "office365", "root", "netadmin"
])
run_step("update-nvd",[PYTHON, "main.py", "update-nvd"])
