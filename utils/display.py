from collections import defaultdict
from occulusint.core.domain_filter import is_subdomain

def export_grouped_domains_txt(data, output_path, score_key="score", fqdn_key="fqdn", min_score=50):
    score_map = defaultdict(list)
    for entry in data:
        try:
            score = int(entry.get(score_key, 0))
            fqdn = entry.get(fqdn_key, "")
            if score >= min_score:
                score_map[score].append(fqdn)
        except Exception:
            continue

    with open(output_path, "w", encoding="utf-8") as f:
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
