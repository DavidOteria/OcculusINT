import sys
import os
import csv
from occulusint.recon.resolve import resolve_domains

def main():
    if len(sys.argv) != 2:
        print("Usage: python -m scripts.resolve <targets/subdomains_file.txt>")
        return

    input_txt = sys.argv[1]
    if not os.path.isfile(input_txt):
        print(f"[!] File not found: {input_txt}")
        return

    # Lecture des sous-domaines
    with open(input_txt, encoding="utf-8") as f:
        domains = [line.strip() for line in f if line.strip()]

    # Résolution
    mapping = resolve_domains(domains)

    # Écriture CSV
    output_csv = input_txt.replace(".txt", "_resolved.csv")
    os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)
    with open(output_csv, "w", newline="", encoding="utf-8") as out:
        writer = csv.writer(out)
        writer.writerow(["domain", "ip"])
        for d, ip in mapping.items():
            writer.writerow([d, ip])

    print(f"\n[+] Resolved {len(mapping)} domains")
    print(f"[+] Results saved to {output_csv}")

if __name__ == "__main__":
    main()
