import sys
import os
from occulusint.recon.google_dork import search_subdomains


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 4:
        print("Usage: python -m scripts.googledork <domain> [<api_key> <cx>]")
        return

    domain = sys.argv[1]
    api_key = sys.argv[2] if len(sys.argv) >= 3 else None
    cx      = sys.argv[3] if len(sys.argv) == 4 else None

    print(f"[~] Searching subdomains for {domain} via Google Dork")
    try:
        subs = search_subdomains(domain, api_key=api_key, cx=cx, num=50)
    except Exception as e:
        print(f"[!] Error: {e}")
        return

    print(f"[+] Found {len(subs)} subdomains:\n")
    for s in subs:
        print(f" - {s}")

    os.makedirs("targets", exist_ok=True)
    out = f"targets/{domain.replace('.', '_')}_googledork.txt"
    with open(out, "w", encoding="utf-8") as f:
        for s in subs:
            f.write(s + "\n")

    print(f"\n[+] Results saved to {out}")


if __name__ == "__main__":
    main()
