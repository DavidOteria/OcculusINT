import sys
import os
import csv
from utils.csv import read_csv, write_csv
from utils.threading import run_parallel
from utils.display import export_grouped_domains_txt
from occulusint.recon.domain_discovery import discover_domains_from_crtsh
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
    print("""
Usage: python main.py <step> <args>

Steps:
  discover   <keyword>
  enum       <input_file.csv>
  resolve    <input_file.csv>
  enrich     <resolved.csv>
  filter     <input_file.csv> <keyword1> <keyword2> ...
""")

def run_discover(keyword):
    domains = discover_domains_from_crtsh(keyword)
    os.makedirs("targets", exist_ok=True)
    out_path = f"targets/{keyword}_domains.csv"
    data = [{"fqdn": domain} for domain in domains]
    write_csv(out_path, data, fieldnames=["fqdn"])
    print(f"[+] Domains saved to {out_path}")

def run_enum(input_path):
    roots = [row["fqdn"] for row in read_csv(input_path)]
    enumerator = SubdomainsEnumerator()
    all_subs = set()

    for root in roots:
        print(f"[~] Enumerating subdomains for: {root}")
        try:
            subs = enumerator.enumerate(root)
            print(f"[+] {len(subs)} subdomains found for {root}")
            all_subs.update(subs)
        except Exception as e:
            print(f"[!] Error while enumerating {root}: {e}")

    out_path = input_path.replace(".csv", "_subdomains.csv")
    data = [{"fqdn": sub} for sub in sorted(all_subs)]
    write_csv(out_path, data, fieldnames=["fqdn"])
    print(f"[✔] Subdomains saved to {out_path}")

def run_resolve(input_path):
    domains = [row["fqdn"] for row in read_csv(input_path)]
    results = resolve_domains(domains)
    out = input_path.replace(".csv", "_resolved.csv")
    data = [{"domain": d, "ip": ip} for d, ip in results.items()]
    write_csv(out, data, fieldnames=["domain", "ip"])
    print(f"[+] Resolved IPs saved to {out}")

def run_enrich(input_csv):
    records = read_csv(input_csv)
    out = input_csv.replace(".csv", "_enriched.csv")

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

    results, _ = run_parallel(enrich_record, records, max_workers=20)
    write_csv(out, results, fieldnames=[
        "domain", "ip", "asn", "network_name",
        "country", "region", "city", "provider"
    ])
    print(f"[+] Enriched data saved to {out}")

def run_filter(input_path, keywords):
    from utils.display import export_grouped_domains_txt

    domains = [row["fqdn"] for row in read_csv(input_path)]
    scored = score_domains_parallel(domains, keywords, show_progress=True)

    out_csv = input_path.replace(".csv", "_filtered.csv")
    out_txt = input_path.replace(".csv", "_filtered.txt")

    data = []
    for fqdn, score in scored:
        type_ = "subdomain" if is_subdomain(fqdn) else "root"
        data.append({"fqdn": fqdn, "score": score, "type": type_})

    write_csv(out_csv, data, fieldnames=["fqdn", "score", "type"])
    export_grouped_domains_txt(data, out_txt)

    print(f"[+] Filtered and scored domains saved to:\n  - {out_csv}\n  - {out_txt}")


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