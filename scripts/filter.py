# scripts/filter.py

import sys
import os
from collections import defaultdict
from occulusint.core.domain_filter import score_domains_parallel, is_subdomain

def main():
    if len(sys.argv) < 3:
        print("Usage: python -m scripts.filter <targets/file.txt> <kw1> [<kw2> ...]")
        return

    input_path = sys.argv[1]
    keywords   = [kw.lower() for kw in sys.argv[2:]]

    if not os.path.isfile(input_path):
        print(f"[!] File not found: {input_path}")
        return

    # Lecture des domaines bruts
    with open(input_path, encoding="utf-8") as f:
        raw_domains = [line.strip() for line in f if line.strip()]

    # Deep scan (HTTP + DNS) en parallèle
    print(f"[~] Scoring {len(raw_domains)} domains for keywords: {keywords}")
    deep_scores = score_domains_parallel(
        raw_domains,
        keywords,
        max_workers=20,
        show_progress=True
    )

    # Filtrage par seuil
    threshold = 50
    filtered = [(d, s) for d, s in deep_scores if s >= threshold]

    # Affichage console
    print(f"\n[+] {len(filtered)} domains retained (score ≥ {threshold}):\n")
    for domain, score in filtered:
        print(f" - {domain} (score {score})")

    # Écriture groupée par score
    os.makedirs("targets", exist_ok=True)
    output_path = input_path.replace(".txt", "_filtered.txt")
    with open(output_path, "w", encoding="utf-8") as out_f:
        score_map = defaultdict(list)
        for domain, score in filtered:
            score_map[score].append(domain)

        for score in sorted(score_map.keys(), reverse=True):
            out_f.write(f"score {score}:\n")

            # Séparer racines et sous-domaines
            roots = [d for d in score_map[score] if not is_subdomain(d)]
            subs  = [d for d in score_map[score] if is_subdomain(d)]

            if roots:
                out_f.write("  == Root domains ==\n")
                for d in roots:
                    out_f.write(f"    - {d}\n")
            if subs:
                out_f.write("  == Subdomains ==\n")
                for d in subs:
                    out_f.write(f"    - {d}\n")

            out_f.write("\n")

    print(f"\n[+] Results saved to {output_path}")

if __name__ == "__main__":
    main()
