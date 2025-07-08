from collections import defaultdict
from occulusint.core.filter import is_subdomain

def export_grouped_domains_txt(data, output_path, score_key="score", fqdn_key="fqdn", min_score=50):
    """
    Write domains grouped by score to a text file.

    :param data: Iterable of dicts containing at least *score_key* and *fqdn_key*
    :param output_path: Destination .txt file
    :param score_key: Dict key where the score is stored (default "score")
    :param fqdn_key: Dict key for the FQDN (default "fqdn")
    :param min_score: Minimum score to include in the output
    :return: None
    """
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

def export_root_vs_sub_txt(data, output_path, fqdn_key="fqdn"):
    """
    Split a list of FQDNs into root domains vs sub-domains and write a text file.

    :param data: Iterable of dicts containing at least *fqdn_key*
    :param output_path: Destination .txt file
    :param fqdn_key: Dict key for the FQDN (default "fqdn")
    :return: None
    """
    roots = []
    subs = []

    for row in data:
        fqdn = row.get(fqdn_key, "")
        if is_subdomain(fqdn):
            subs.append(fqdn)
        else:
            roots.append(fqdn)

    with open(output_path, "w", encoding="utf-8") as f:
        if roots:
            f.write("== Root domains ==\n")
            for d in sorted(roots):
                f.write(f"  - {d}\n")
            f.write("\n")
        if subs:
            f.write("== Subdomains ==\n")
            for d in sorted(subs):
                f.write(f"  - {d}\n")
