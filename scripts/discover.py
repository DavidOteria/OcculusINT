# scripts/discover.py

import sys
from occulusint.recon.domain_discovery import discover_domains_from_crtsh
import os


def main():
    if len(sys.argv) > 1:
        keyword = sys.argv[1]
    else:
        keyword = input("Entrez un mot-clé pour la recherche crt.sh (ex: bnp) : ")

    print(f"\n[~] Recherche de domaines contenant : {keyword}")
    domains = discover_domains_from_crtsh(keyword)

    print(f"\n[+] {len(domains)} domaines trouvés contenant '{keyword}' :\n")
    for d in domains:
        print(f" - {d}")

    os.makedirs("targets", exist_ok=True)
    output_file = f"targets/{keyword}_domains.txt"
    with open(output_file, "w") as f:
        for d in domains:
            f.write(d + "\n")

    print(f"\n[+] Résultats enregistrés dans {output_file}")


if __name__ == "__main__":
    main()
