# scripts/enrich.py

import sys
import os
import csv
from occulusint.enrich.ip_enrichment import (
    get_asn_info,
    get_geolocation,
    detect_cloud_provider
)

def main():
    if len(sys.argv) != 2:
        print("Usage: python -m scripts.enrich <targets/file_resolved.csv>")
        return

    input_csv = sys.argv[1]
    if not os.path.isfile(input_csv):
        print(f"[!] File not found: {input_csv}")
        return

    output_csv = input_csv.replace("_resolved.csv", "_enriched.csv")
    os.makedirs("targets", exist_ok=True)

    with open(input_csv, newline='', encoding='utf-8') as infile, \
         open(output_csv, 'w', newline='', encoding='utf-8') as outfile:

        reader = csv.DictReader(infile)
        fieldnames = [
            "domain", "ip", "asn", "network_name",
            "country", "region", "city", "provider"
        ]
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for record in reader:
            domain = record["domain"]
            ip_address = record["ip"]

            asn, network_name = get_asn_info(ip_address)
            geo_info = get_geolocation(ip_address)
            provider = detect_cloud_provider(asn, network_name)

            writer.writerow({
                "domain":       domain,
                "ip":           ip_address,
                "asn":          asn,
                "network_name": network_name,
                "country":      geo_info.get("country", ""),
                "region":       geo_info.get("region", ""),
                "city":         geo_info.get("city", ""),
                "provider":     provider
            })

            print(f"[+] {domain} -> {ip_address} | ASN: {asn} | Provider: {provider} | Country: {geo_info.get('country','-')}")

    print(f"\n[+] Enriched data saved to {output_csv}")

if __name__ == "__main__":
    main()
