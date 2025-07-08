import csv
import ipaddress
import pathlib
import requests
from typing import Any, Dict, List, Optional
from shodan import Shodan, APIError
from utils.shodan_helpers import (
    extract_nested,
    query_shodan,
    query_internetdb,
)
from utils.scoring import compute_security_score


FIELDS_BANNER = [
    "product",
    "version",
    "http.title",
    "ssh.banner",
    "ssl.cipher",
    "ssl.cert.subject.CN",
]

CSV_FIELD_ORDER = [
    "domain", "ip", "ports", "vulns",
    "product", "version", "http.title",
    "ssh.banner", "ssl.cipher", "ssl.cert.subject.CN",
    "os", "org", "asn"
]
def passive_vuln_scan(
    input_csv: str | pathlib.Path,
    output_csv: str | pathlib.Path,
    api_key: Optional[str],
    use_internetdb: bool = False) -> None:
    if not use_internetdb and not api_key:
        raise ValueError("Shodan API key required unless use_internetdb=True")
    
    """
    Passive vulnerability scan using Shodan or InternetDB.
    :param input_csv: Input file path with 'ip' (and optional 'domain') columns
    :param output_csv: Output path for enriched vulnerabilities
    :param api_key: Shodan API key (ignored if use_internetdb=True)
    :param use_internetdb: If True, use public InternetDB instead of Shodan

    Enriches input CSV (IP, domain) with OSINT data and writes two outputs:
    - <name>_vuln.csv: raw info (ports, CVEs, banner metadata)
    - <name>_score.csv: computed scores (tls/vuln/exposure/hygiene)"""

    input_csv = pathlib.Path(input_csv)
    output_csv = pathlib.Path(output_csv)

    unique_ips: Dict[str, Dict[str, Any]] = {}

    with input_csv.open(newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip_str = (row.get("ip") or row.get("IP") or "").strip()
            if not ip_str:
                continue
            try:
                ipaddress.ip_address(ip_str)
            except ValueError:
                print(f"[!] Invalid IP skipped: {ip_str}")
                continue
            domain = row.get("domain", row.get("fqdn", "")).strip()
            unique_ips.setdefault(ip_str, {"domain": domain})

    print(f"[*] IPs to query: {len(unique_ips)}")

    api = None if use_internetdb else Shodan(api_key)

    for ip in list(unique_ips):
        try:
            data = query_internetdb(ip) if use_internetdb else query_shodan(api, ip)
        except (APIError, requests.RequestException) as e:
            print(f"[!] {ip} skipped: {e}")
            unique_ips.pop(ip, None)
            continue

        row = {
            "domain": unique_ips[ip]["domain"],
            "ip": ip,
            "ports": ";".join(map(str, data.get("ports", []))),
            "vulns": ";".join(data.get("vulns", [])),
            "os": data.get("os", ""),
            "org": data.get("org", ""),
            "asn": data.get("asn", "")
        }

        for banner in data.get("data", []):
            for field in FIELDS_BANNER:
                if field not in row:
                    value = extract_nested(banner, field)
                    if value:
                        row[field] = str(value)
            if all(field in row for field in FIELDS_BANNER):
                break

        unique_ips[ip] = row

    with output_csv.open("w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=CSV_FIELD_ORDER)
        writer.writeheader()
        writer.writerows(unique_ips.values())

    print(f"[+] Vuln report saved to {output_csv}")

    score_path = output_csv.with_name(output_csv.stem.replace("_vuln", "_score") + ".csv")
    with score_path.open("w", newline="", encoding="utf-8") as f_score:
        writer = csv.DictWriter(f_score, fieldnames=[
            "domain", "ip", "tls_score", "vuln_score", "exposure_score", "hygiene_score", "total_score"
        ])
        writer.writeheader()
        for row in unique_ips.values():
            total, breakdown = compute_security_score(row)
            writer.writerow({
                "domain": row["domain"],
                "ip": row["ip"],
                "tls_score": breakdown["tls"],
                "vuln_score": breakdown["vuln"],
                "exposure_score": breakdown["exposure"],
                "hygiene_score": breakdown["hygiene"],
                "total_score": total
            })
    print(f"[+] Score report saved to {score_path}")