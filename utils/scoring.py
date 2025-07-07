"""Security‑score computation for the passive vuln scan.  All constants are
co‑located for easy tuning.
"""

from __future__ import annotations

import re
from typing import Dict, Tuple

from .nvd_cache import get_cvss

# ------------------------------------------------------------
# Tunable weights
# ------------------------------------------------------------
TLS_MAX = 25
VULN_MAX = 35
EXPOSURE_MAX = 25
HYGIENE_MAX = 15
TOTAL_MAX = TLS_MAX + VULN_MAX + EXPOSURE_MAX + HYGIENE_MAX  # 100

# Ports considered risky when exposed to the Internet
RISKY_PORTS = {21, 23, 445, 3389}

DEFAULT_TITLE_REGEX = re.compile(r"default|test|welcome", re.I)


# ------------------------------------------------------------
# Public function
# ------------------------------------------------------------

def compute_security_score(row: Dict[str, str]) -> Tuple[int, Dict[str, int]]:
    """Compute (total, breakdown) for a single CSV row.

    *row* is the dict produced by *passive_vuln_scan* (strings for every column).
    """
    breakdown: Dict[str, int] = {
        "tls": 0,
        "vuln": 0,
        "exposure": 0,
        "hygiene": 0,
    }

    # ---------------- TLS ----------------
    cipher = row.get("ssl.cipher", "")
    if "TLSv1.3" in cipher:
        breakdown["tls"] = TLS_MAX
    elif "TLSv1.2" in cipher:
        breakdown["tls"] = int(TLS_MAX * 0.6)  # 15
    elif cipher:
        breakdown["tls"] = 0
    if any(x in cipher for x in ("RC4", "3DES", "DES")):
        breakdown["tls"] = max(0, breakdown["tls"] - 10)

    # ---------------- Vulnerabilities ----------------
    cves = [c for c in row.get("vulns", "").split(";") if c]
    if not cves:
        breakdown["vuln"] = VULN_MAX
    else:
        worst = 0.0
        for cve in cves:
            cvss = get_cvss(cve)
            if cvss is None:
                # Unknown CVE → treat as medium (heuristic 5.0)
                cvss = 5.0
            worst = max(worst, cvss)
        if worst < 4.0:
            breakdown["vuln"] = int(VULN_MAX * 0.7)  # 25
        elif worst < 7.0:
            breakdown["vuln"] = int(VULN_MAX * 0.4)  # 15
        elif worst < 9.0:
            breakdown["vuln"] = int(VULN_MAX * 0.15)  # 5
        else:
            breakdown["vuln"] = 0

    # ---------------- Exposure ----------------
    ports = {int(p) for p in row.get("ports", "").split(";") if p}
    score = EXPOSURE_MAX
    if ports & RISKY_PORTS:
        score -= 10
    if any(p for p in ports if p not in {80, 443} and p < 1024):
        score -= 5
    breakdown["exposure"] = max(0, score)

    # ---------------- Hygiene ----------------
    title = row.get("http.title", "")
    if title and not DEFAULT_TITLE_REGEX.search(title):
        breakdown["hygiene"] = HYGIENE_MAX
    else:
        breakdown["hygiene"] = int(HYGIENE_MAX * 0.33)  # 5

    total = sum(breakdown.values())
    return total, breakdown