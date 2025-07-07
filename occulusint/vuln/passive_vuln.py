"""
passive_vuln.py – Passive vulnerability scanner using Shodan **with CVSS-aware scoring**
======================================================================================

Given a CSV file that contains at least an **ip** column (and optionally a
**domain** column for readability), this module looks up every unique IP via
*Shodan Host API* and produces two artefacts next to the input file::

    <name>_vuln.csv   – raw enrichment (ports, CVE list, banners, org…)
    <name>_score.csv  – synthetic scores (TLS / vuln / exposure / hygiene)

The scan is **passive**: only OSINT data hosted by Shodan is queried – no new
packets are sent to the target.

Typical CLI flow::

    python main.py passive-vuln resolved.csv SHODAN_API_KEY

Notes
-----
* The Starter (100‑credit) plan allows unlimited ``/shodan/host/{ip}`` calls but
  rate‑limited to **1 request per second**. We honour this with ``RATE_LIMIT``.
* Every API response is cached on disk (``.cache/shodan/<ip>.json``) so that
  repeated runs during development do not burn extra time/quota.
* If *no* API key is provided you can fall back to **InternetDB** (public
  endpoint maintained by Shodan) which returns only ``ports`` and ``vulns``.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import pathlib
import time
from typing import Any, Dict, List, Optional

import requests  # used only when falling back to InternetDB
from shodan import APIError, Shodan

from utils.scoring import compute_security_score

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

# Where we cache raw JSON responses to avoid hammering the API during testing
CACHE_DIR = pathlib.Path(".cache/shodan")
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Shodan allows 1 request/second on every membership plan.
RATE_LIMIT = 1.1  # seconds – leave a small margin

# ---------------------------------------------------------------------------
# Field selection helpers – tune once, reuse everywhere
# ---------------------------------------------------------------------------

# Keys we want to extract from *each* banner inside ``data``.
# Dotted notation → walk nested dicts step by step.
FIELDS_BANNER: List[str] = [
    "product",                   # service name ("nginx", "Microsoft IIS" …)
    "version",                   # version string if parsed ("1.24.0")
    "http.title",                # HTML title captured on port 80/443
    "ssh.banner",                # raw SSH identification banner
    "ssl.cipher",                # negotiated TLS cipher suite
    "ssl.cert.subject.CN",       # leaf certificate Common Name
]

# Column order for the enrichment CSV – adjust to your liking.
CSV_FIELD_ORDER: List[str] = [
    "domain",
    "ip",
    "ports",
    "vulns",
    "product",
    "version",
    "http.title",
    "ssh.banner",
    "ssl.cipher",
    "ssl.cert.subject.CN",
    "os",
    "org",
    "asn",
]

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_nested(source: Dict[str, Any], dotted_path: str) -> Optional[Any]:
    """Safely walk *source* following ``dotted_path`` ("a.b.c")."""
    cur: Any = source
    for part in dotted_path.split('.'):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


def _load_cache(ip: str) -> Optional[Dict[str, Any]]:
    p = CACHE_DIR / f"{ip}.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except json.JSONDecodeError:
            p.unlink(missing_ok=True)
    return None


def _save_cache(ip: str, data: Dict[str, Any]) -> None:
    (CACHE_DIR / f"{ip}.json").write_text(json.dumps(data))


def _query_shodan_host(api: Shodan, ip: str) -> Dict[str, Any]:
    cached = _load_cache(ip)
    if cached:
        return cached

    data = api.host(ip, history=False)
    _save_cache(ip, data)
    time.sleep(RATE_LIMIT)
    return data


def _query_internetdb(ip: str) -> Dict[str, Any]:
    url = f"https://internetdb.shodan.io/{ip}"
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    raw = resp.json()
    # Normalise so the downstream code stays identical.
    return {
        "ip_str": ip,
        "ports": raw.get("ports", []),
        "vulns": raw.get("vulns", []),
        "data": [],
    }

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def passive_vuln_scan(
    input_csv: str | pathlib.Path,
    output_csv: str | pathlib.Path,
    api_key: str | None,
    *,
    use_internetdb: bool = False,
) -> None:
    """Passive vuln scan + scoring.

    Parameters
    ----------
    input_csv : str or Path
        CSV with at least an ``ip`` column. ``domain`` is optional (kept for
        readability).
    output_csv : str or Path
        File to create for the enrichment (``*_vuln.csv``). Overwritten if it
        exists.
    api_key : str or None
        Shodan API key. Ignored when *use_internetdb* is True.
    use_internetdb : bool, default False
        Fall back to the free InternetDB endpoint (limited info, no key
        required).
    """

    if not use_internetdb and not api_key:
        raise ValueError("Shodan API key required or enable use_internetdb=True")

    input_csv = pathlib.Path(input_csv)
    output_csv = pathlib.Path(output_csv)

    # ---------------------------------------------------------------------
    # 1. Parse input – keep first domain per unique IP
    # ---------------------------------------------------------------------
    seen_ips: Dict[str, Dict[str, Any]] = {}

    with input_csv.open(newline='', encoding='utf-8') as f_in:
        reader = csv.DictReader(f_in)
        for row in reader:
            ip_raw = (row.get("ip") or row.get("IP") or "").strip()
            if not ip_raw:
                continue
            try:
                ipaddress.ip_address(ip_raw)
            except ValueError:
                print(f"[!] Skipping invalid IP: {ip_raw}")
                continue
            domain = row.get("domain", row.get("fqdn", "")).strip()
            seen_ips.setdefault(ip_raw, {"domain": domain})

    print(f"[*] Unique IPs to query: {len(seen_ips)}")

    # ---------------------------------------------------------------------
    # 2. Query Shodan / InternetDB and build enrichment rows
    # ---------------------------------------------------------------------
    api = None if use_internetdb else Shodan(api_key)  # type: ignore[assignment]

    for ip in list(seen_ips):  # copy to allow removal on error
        try:
            data = _query_internetdb(ip) if use_internetdb else _query_shodan_host(api, ip)  # type: ignore[arg-type]
        except (APIError, requests.RequestException) as exc:
            print(f"[!] {ip} skipped: {exc}")
            seen_ips.pop(ip, None)
            continue

        # --- root‑level fields ------------------------------------------------
        row: Dict[str, Any] = {
            "domain": seen_ips[ip]["domain"],
            "ip": ip,
            "ports": ";".join(map(str, data.get("ports", []))),
            "vulns": ";".join(data.get("vulns", [])),
            "os": data.get("os", ""),
            "org": data.get("org", ""),
            "asn": data.get("asn", ""),
        }

        # --- banner fields ----------------------------------------------------
        banner_seen: Dict[str, str] = {}
        for banner in data.get("data", []):
            for dotted in FIELDS_BANNER:
                if dotted in banner_seen:
                    continue
                val = _extract_nested(banner, dotted)
                if val:
                    banner_seen[dotted] = str(val)
            if len(banner_seen) == len(FIELDS_BANNER):
                break
        row.update(banner_seen)
        seen_ips[ip] = row

    # ---------------------------------------------------------------------
    # 3. Write enrichment CSV
    # ---------------------------------------------------------------------
    with output_csv.open("w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=CSV_FIELD_ORDER)
        writer.writeheader()
        writer.writerows(seen_ips.values())

    print(f"[+] Passive‑vuln report written to {output_csv} – {len(seen_ips)} rows")

    # ---------------------------------------------------------------------
    # 4. Compute CVSS-aware scores and write second CSV
    # ---------------------------------------------------------------------
    score_path = output_csv.with_name(output_csv.stem.replace("_vuln", "_score") + ".csv")
    with score_path.open("w", newline="", encoding="utf-8") as f_sc:
        score_fields = [
            "domain", "ip",
            "tls_score", "vuln_score", "exposure_score", "hygiene_score",
            "total_score",
        ]
        writer = csv.DictWriter(f_sc, fieldnames=score_fields)
        writer.writeheader()
        for row in seen_ips.values():
            total, br = compute_security_score(row)
            writer.writerow({
                "domain": row["domain"],
                "ip": row["ip"],
                "tls_score": br["tls"],
                "vuln_score": br["vuln"],
                "exposure_score": br["exposure"],
                "hygiene_score": br["hygiene"],
                "total_score": total,
            })
    print(f"[+] Score report written to {score_path}")