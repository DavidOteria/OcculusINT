#!/usr/bin/env python3

import sys
import os
import csv
import pathlib
import pandas
from utils.csv import read_csv, write_csv
from utils.threading import run_parallel
from utils.display import export_grouped_domains_txt, export_root_vs_sub_txt
from utils.enrich import enrich_record
from utils.nvd_cache import load_cache
from utils.enrich import enrich_record
from utils.display import export_root_vs_sub_txt
from occulusint.recon.domain_discovery import discover_domains_from_crtsh
from occulusint.recon.subdomains import SubdomainsEnumerator
from occulusint.recon.resolve import resolve_domains, is_reachable
from occulusint.vuln.passive_vuln import passive_vuln_scan
from occulusint.enrich.ip_enrichment import (
    get_asn_info,
    get_geolocation,
    detect_cloud_provider
)
from occulusint.core.filter import (
    score_domains_parallel,
    is_subdomain,
    score_to_label
)


def show_banner():
    print(r"""
     ██████╗  ██████╗ ██████╗██╗   ██╗██╗     ██╗   ██╗███████╗██╗███╗   ██╗████████╗
    ██╔═══██╗██╔════╝██╔════╝██║   ██║██║     ██║   ██║██╔════╝██║████╗  ██║╚══██╔══╝
    ██║   ██║██║     ██║     ██║   ██║██║     ██║   ██║███████╗██║██╔██╗ ██║   ██║   
    ██║   ██║██║     ██║     ██║   ██║██║     ██║   ██║╚════██║██║██║╚██╗██║   ██║   
    ╚██████╔╝╚██████╗╚██████╗╚██████╔╝███████╗╚██████╔╝███████║██║██║ ╚████║   ██║   
     ╚═════╝  ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   
        Open-Source Recon Tool - Your Eye on the External Surface
            https://github.com/DavidOteria/OcculusINT
    """)

def usage():
    print("""OcculusINT - Open Source Intelligence Scanner
          
Usage: python main.py <step> [options]

Steps:
  -d, --discover        <keyword>                       Discover subdomains from keyword
  -e, --enum            <input_file.csv>                Enumerate data from collected domains
  -r, --resolve         <input_file.csv>                Resolve domains to IPs
  -v, --passive-vuln    <resolved.csv> <SHODAN_API_KEY> Query Shodan for passive vulnerability data
  -n, --enrich          <resolved.csv>                  Enrich resolved IPs with ASN and geo info
  -f, --filter          <input_file.csv> <keywords...>  Filter rows matching given keywords
  -u, --update-nvd                                      Update local NVD CVE database
  -m, --merge           <resolved.csv>                  Merge resolved, filtered, vuln_score, and enriched data

Examples:
  python main.py -d X
  python main.py -e targets/X_domains.csv
  python main.py -r targets/X_domains_subdomains.csv
  python main.py -v targets/X_domains_resolved.csv SHODAN_API_KEY
  python main.py -n targets/X_domains_resolved.csv
  python main.py -f targets/X_domains_resolved.csv apache nginx
  python main.py -m targets/X_domains_resolved.csv

OcculusINT v1.0 | by Oteria OSINT TEAM
""")

def run_discover(keywords):
    """
    Discover root domains via crt.sh and save to CSV.

    :param keywords: list of strings used as crt.sh search keywords
    :return: None – writes targets/<joined>_domains.csv
    """
    domains = discover_domains_from_crtsh(keywords)
    os.makedirs("targets", exist_ok=True)
    joined = "_".join(keywords)
    out_path = f"targets/{joined}_domains.csv"
    data = [{"fqdn": domain} for domain in domains]
    write_csv(out_path, data, fieldnames=["fqdn"])
    print(f"[+] Domains saved to {out_path}")

def run_enum(domain: str):
    """
    Enumerate subdomains for a single domain using all available engines.
    Results are saved to 'targets/<domain>_subdomains.csv'.

    :param domain: Root domain to enumerate (e.g. 'google.com')
    """
    enumerator = SubdomainsEnumerator()

    print(f"[~] Enumerating subdomains for: {domain}")
    try:
        subs = enumerator.enumerate(domain)
        print(f"[+] {len(subs)} subdomains found for {domain}")
    except Exception as e:
        print(f"[!] Enumeration failed: {e}")
        return

    os.makedirs("targets", exist_ok=True)
    out_path = f"targets/{domain}_subdomains.csv"
    data = [{"fqdn": sub} for sub in sorted(subs)]
    write_csv(out_path, data, fieldnames=["fqdn"])
    print(f"[✔] Subdomains saved to {out_path}")

def run_resolve(input_path):
    """
    Resolve every FQDN in <input_path> to its IP address,
    and check TCP reachability on port 443.

    :param input_path: CSV containing 'fqdn' or 'domain' column
    :return: None – writes *_resolved.csv with columns [domain, ip, reachable]
    """
    rows = read_csv(input_path)

    domains = [
        (row.get("fqdn") or row.get("domain")).strip()
        for row in rows
        if row.get("fqdn") or row.get("domain")
    ]

    if not domains:
        print("[!] No valid domain found in the file.")
        return

    results = resolve_domains(domains)
    
    out = input_path.replace(".csv", "_resolved.csv")
    data = []
    for d, ip in results.items():
        reachable = is_reachable(ip)
        data.append({
            "domain": d,
            "ip": ip,
            "reachable": reachable
            })
    write_csv(out, data, fieldnames=["domain", "ip", "reachable"])

    print(f"[+] Resolved IPs saved to {out}")

def run_passive_vuln(input_csv: str, api_key: str):
    """
    Enrich <input_csv> with Shodan data and compute scores.

    :param input_csv: <name>_resolved.csv
    :param api_key: Shodan API key
    :return: None – writes *_vuln.csv and *_vuln_score.csv
    """
    out_vuln       = input_csv.replace(".csv", "_vuln.csv")
    out_vuln_score = input_csv.replace(".csv", "_vuln_score.csv")
    passive_vuln_scan(
        input_csv,
        out_vuln,
        api_key,
        score_path=out_vuln_score
    )
    print(f"[+] Vuln  file : {out_vuln}")
    print(f"[+] Score file: {out_vuln_score}")

def run_enrich(input_csv):
    """
    Add ASN / geolocation / cloud info to each (domain, IP) row.

    :param input_csv: *_resolved.csv
    :return: None – writes *_enriched.csv
    """
    records_raw = read_csv(input_csv)
    records = []
    for row in records_raw:
        ip = row.get("ip", "").strip()
        fqdn = row.get("fqdn") or row.get("domain")
        if fqdn and ip:
            records.append({"domain": fqdn.strip(), "ip": ip})

    if not records:
        print("[!] Aucun couple domaine/IP valide trouvé dans le fichier.")
        return

    out_csv = input_csv.replace(".csv", "_enriched.csv")

    results, _ = run_parallel(enrich_record, records, max_workers=20, show_progress=True)

    write_csv(out_csv, results, fieldnames=[
        "domain", "ip", "asn", "network_name",
        "country", "region", "city", "provider"
    ])

    print(f"[+] Enriched data saved to {out_csv}")

def run_filter(input_path, keywords):
    """
    Score and filter domains according to keyword set.

    :param input_path: CSV to score
    :param keywords: list/iterable of keywords used for scoring
    :return: None – writes *_filtered.csv + *_filtered.txt
    """
    rows = read_csv(input_path)
    domains = []

    for row in rows:
        fqdn = row.get("fqdn") or row.get("domain")
        if fqdn:
            domains.append(fqdn.strip())

    scored = score_domains_parallel(domains, keywords, show_progress=True)

    out_csv = input_path.replace(".csv", "_filtered.csv")
    out_txt = input_path.replace(".csv", "_filtered.txt")

    data = []
    for fqdn, score, status in scored:
        type_ = "subdomain" if is_subdomain(fqdn) else "root"
        criticity = score_to_label(score)
        data.append({
            "fqdn": fqdn,
            "score": score,
            "https_status": status,
            "type": type_,
            "criticité": criticity
        })

    write_csv(out_csv, data, fieldnames=["fqdn", "score","https_status", "type", "criticité"])

    export_root_vs_sub_txt(data, out_txt)

    print(f"[+] Filtered and scored domains saved to:\n  - {out_csv}\n  - {out_txt}")

def run_update_nvd():
    """Download / refresh the NVD feed (CVSS cache)."""
    load_cache(force=True)
    print("[+] NVD CVSS cache successfully updated.")

def run_merge(base_path):
    """
    Merge resolved, filtered, vuln_score, and enriched files for a given base.

    :param base_path: path to the *_resolved.csv file
    :return: None – writes *_final.csv
    """
    import pandas as pd

    base = base_path.replace("_resolved.csv", "")
    files = {
        "resolved": f"{base}_resolved.csv",
        "filtered": f"{base}_filtered.csv",
        "vuln": f"{base}_vuln_score.csv",
        "enriched": f"{base}_enriched.csv"
    }

    dfs = {}
    for name, path in files.items():
        if os.path.exists(path):
            dfs[name] = pd.read_csv(path)
        else:
            print(f"[!] Warning: {name} file not found: {path}")

    # Fusion progressive
    df = dfs.get("resolved", pd.DataFrame())
    for key in ["filtered", "vuln", "enriched"]:
        if key in dfs:
            df = pd.merge(df, dfs[key], on=["domain", "ip"], how="left")

    out_path = f"{base}_final.csv"
    df.to_csv(out_path, index=False)
    print(f"[✔] Final consolidated file saved as: {out_path}")

def main():
    show_banner()

    if len(sys.argv) < 2:
        usage()
        return

    cmd = sys.argv[1]

    if cmd == "-d" or cmd == "--discover" and len(sys.argv) >= 3:
        run_discover(sys.argv[2:])
    elif cmd == "-e" or cmd == "--enum" and len(sys.argv) == 3:
        run_enum(sys.argv[2])
    elif cmd == "-r" or cmd == "--resolve" and len(sys.argv) == 3:
        run_resolve(sys.argv[2])
    elif cmd == "-v" or cmd == "--passive-vuln" and len(sys.argv) == 4:
        run_passive_vuln(sys.argv[2], sys.argv[3])
    elif cmd == "-n" or cmd == "--enrich" and len(sys.argv) == 3:
        run_enrich(sys.argv[2])
    elif cmd == "-f" or cmd == "filter" and len(sys.argv) >= 4:
        run_filter(sys.argv[2], sys.argv[3:])
    elif cmd == "update-nvd" and len(sys.argv) == 2:
        run_update_nvd()
    elif cmd == "-m" or cmd == "--merge" and len(sys.argv) == 3:
        run_merge(sys.argv[2])
    else:
        usage()

if __name__ == "__main__":
    main()
