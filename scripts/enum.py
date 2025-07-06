# scripts/enum.py

from occulusint.recon.subdomains import SubdomainEnumerator
import sys


def main():
    if len(sys.argv) != 2:
        print("Usage: python scripts/enum.py <domain>")
        return

    domain = sys.argv[1]
    enumerator = SubdomainEnumerator()
    results = enumerator.enumerate(domain)

    print(f"\n[+] Found {len(results)} subdomains for {domain}:\n")
    for sub in results:
        print(f" - {sub}")


if __name__ == "__main__":
    main()
