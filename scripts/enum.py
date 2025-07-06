# scripts/enum.py

from occulusint.recon.subdomains import SubdomainsEnumerator
import sys
import os 


def main():

    os.makedirs("targets", exist_ok=True)

    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else : 
        domain = input("Entrez le domain que vous souhaitez scanner : ")

    enumerator = SubdomainsEnumerator()
    results = enumerator.enumerate(domain)

    print(f"\n[+] Found {len(results)} subdomains for {domain}:\n")
    for sub in results:
        print(f" - {sub}")

    output_path = f"targets/{domain}_subdomains.txt"
    with open(output_path, "w") as f:
        for sub in results:
            f.write(sub + "\n")

    print(f"\n[+] Results saved to {output_path}")


if __name__ == "__main__":
    main()
