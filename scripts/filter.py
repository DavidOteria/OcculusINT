# scripts/filter.py

import sys
import os
from collections import defaultdict
from occulusint.core.domain_filter import (
    static_score_domain,
    score_domains_parallel,
    is_subdomain
)

def main():
    if len(sys.argv) != 3:
        print("Usage: python -m scripts.filter <targets/file.txt> <keyword>")
        return

    input_path, keyword = sys.argv[1], sys.argv[2]
    if not os.path.isfile(input_path):
        print(f"[!] File not found: {input_path}")
        return

    with open(input_path) as f:
        raw_domains = [l.strip() for l in f if l.strip()]

    # 1) Fast pass (static)
    fast = [(d, static_score_domain(d, keyword)) for d in raw_domains]
    fast_sorted = sorted(fast, key=lambda x: x[1], reverse=True)

    # 2) Deep pass limited to top N, with progress bar
    top_n = 50
    candidates = [d for d, _ in fast_sorted[:top_n]]
    deep_scores = score_domains_parallel(
        candidates,
        keyword,
        max_workers=20,
        show_progress=True     # ← on ACTIVE la barre de progression
    )

    # Merge scores: deep override static for candidates
    deep_map = {d: s for d, s in deep_scores}
    all_scores = [(d, deep_map.get(d, fast_score)) for d, fast_score in fast]

    # Filter by threshold
    threshold = 50
    filtered = [(d, s) for d, s in all_scores if s >= threshold]

    print(f"\n[+] {len(filtered)} domaines gardés (score ≥ {threshold}) :")
    for d, s in filtered:
        print(f" - {d} (score {s})")

    # Group & write
    os.makedirs("targets", exist_ok=True)
    output_path = input_path.replace(".txt", "_filtered.txt")
    with open(output_path, "w") as f:
        score_map = defaultdict(list)
        for d, s in filtered:
            score_map[s].append(d)

        for score in sorted(score_map, reverse=True):
            f.write(f"score {score}:\n")
            roots = [d for d in score_map[score] if not is_subdomain(d)]
            subs  = [d for d in score_map[score] if is_subdomain(d)]
            if roots:
                f.write("  == Root domains ==\n")
                for d in roots:
                    f.write(f"    - {d}\n")
            if subs:
                f.write("  == Subdomains ==\n")
                for d in subs:
                    f.write(f"    - {d}\n")
            f.write("\n")

    print(f"\n[+] Résultats sauvegardés dans {output_path}")

if __name__ == "__main__":
    main()
