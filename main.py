# main.py

import sys
import os
import time
from occulusint.recon.domain_discovery import discover_from_crtsh
from occulusint.recon.subdomains import SubdomainsEnumerator
from occulusint.recon.resolve import resolve_domains
from occulusint.enrich.ip_enrichment import (
    get_asn_info,
    get_geolocation,
    detect_cloud_provider
)
from occulusint.core.domain_filter import (
    score_domains_parallel,
    is_subdomain
)

def show_banner():
    print(r"""
          
 ██████   ██████  ██████ ██    ██ ██      ██    ██ ███████ ██ ███    ██ ████████ 
██    ██ ██      ██      ██    ██ ██      ██    ██ ██      ██ ████   ██    ██    
██    ██ ██      ██      ██    ██ ██      ██    ██ ███████ ██ ██ ██  ██    ██    
██    ██ ██      ██      ██    ██ ██      ██    ██      ██ ██ ██  ██ ██    ██    
 ██████   ██████  ██████  ██████  ███████  ██████  ███████ ██ ██   ████    ██    
                                                                                 
        Open-Source Recon Tool - Your Eye on the External Surface

                        https://github.com/DavidOteria/OcculusINT
    """)

def usage():
    print("""
Usage: python main.py <step> <args>

Steps:
  discover   <keyword>
  enum       <input_file.txt>
  googledork <domain>
  resolve    <input_file.txt>
  enrich     <resolved.csv>
  filter     <input_file.txt> <kw1> [kw2] ...
""")

def run_discover(keyword):
    domains = discover_from_crtsh(keyword)
    os.makedirs("targets", exist_ok=True)
    out_path = f"targets/{keyword}_domains.txt"
    with open(out_path, "w") as f:
        f.write("\n".join(domains))
    print(f"[+] Domains saved to {out_path}")

def run_enum(input_path):
    with open(input_path) as f:
        roots = [line.strip() for line in f if line.strip()]
    enumerator = SubdomainsEnumerator()
    all_subs = set()
    for root in roots:
        subs = enumerator.enumerate(root)
        all_subs.update(subs)
    out = input_path.replace(".txt", "_subdomains.txt")
    with open(out, "w") as f:
        f.write("\n".join(sorted(all_subs)))
    print(f"[+] Subdomains saved to {out}")

def run_resolve(input_path):
    with open(input_path) as f:
        domains = [line.strip() for line in f if line.strip()]
    results = resolve_domains(domains)
    out = input_path.replace(".txt", "_resolved.csv")
    with open(out, "w") as f:
        f.write("domain,ip\n")
        for d, ip in results.items():
            f.write(f"{d},{ip}\n")
    print(f"[+] Resolved IPs saved to {out}")

def run_enrich(input_csv):
    import csv
    from concurrent.futures import ThreadPoolExecutor, as_completed

    output_csv = input_csv.replace("_resolved.csv", "_enriched.csv")
    os.makedirs("targets", exist_ok=True)

    with open(input_csv, newline='', encoding='utf-8') as inp:
        reader = csv.DictReader(inp)
        records = list(reader)

    def enrich_record(row):
        domain = row["domain"]
        ip = row["ip"]
        asn, netname = get_asn_info(ip)
        geo = get_geolocation(ip)
        provider = detect_cloud_provider(asn, netname)
        return {
            "domain": domain,
            "ip": ip,
            "asn": asn,
            "network_name": netname,
            "country": geo.get("country", ""),
            "region": geo.get("region", ""),
            "city": geo.get("city", ""),
            "provider": provider
        }

    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(enrich_record, row): row for row in records}
        for future in as_completed(futures):
            try:
                enriched = future.result()
                results.append(enriched)
                print(f"[+] {enriched['domain']} → {enriched['provider']} ({enriched['country']})")
            except Exception as e:
                print(f"[!] Error during enrichment: {e}")

    with open(output_csv, "w", newline='', encoding='utf-8') as out:
        fieldnames = [
            "domain", "ip", "asn", "network_name",
            "country", "region", "city", "provider"
        ]
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"\n[+] Enriched data saved to {output_csv}")

def run_filter(input_path, keywords):
    with open(input_path) as f:
        domains = [line.strip() for line in f if line.strip()]
    scored = score_domains_parallel(domains, keywords, show_progress=True)
    filtered = [(d, s) for d, s in scored if s >= 50]
    out = input_path.replace(".txt", "_filtered.txt")
    with open(out, "w") as f:
        from collections import defaultdict
        score_map = defaultdict(list)
        for d, s in filtered:
            score_map[s].append(d)
        for score in sorted(score_map, reverse=True):
            f.write(f"score {score}:\n")
            roots = [d for d in score_map[score] if not is_subdomain(d)]
            subs = [d for d in score_map[score] if is_subdomain(d)]
            if roots:
                f.write("  == Root domains ==\n")
                for d in roots:
                    f.write(f"    - {d}\n")
            if subs:
                f.write("  == Subdomains ==\n")
                for d in subs:
                    f.write(f"    - {d}\n")
            f.write("\n")
    print(f"[+] Filtered domains saved to {out}")

def main():
    show_banner()

    if len(sys.argv) < 2:
        usage()
        return

    cmd = sys.argv[1]

    if cmd == "discover" and len(sys.argv) == 3:
        run_discover(sys.argv[2])
    elif cmd == "enum" and len(sys.argv) == 3:
        run_enum(sys.argv[2])
    elif cmd == "googledork" and len(sys.argv) == 3:
        run_googledork(sys.argv[2])
    elif cmd == "resolve" and len(sys.argv) == 3:
        run_resolve(sys.argv[2])
    elif cmd == "enrich" and len(sys.argv) == 3:
        run_enrich(sys.argv[2])
    elif cmd == "filter" and len(sys.argv) >= 4:
        run_filter(sys.argv[2], sys.argv[3:])
    else:
        usage()

if __name__ == "__main__":
    main()
