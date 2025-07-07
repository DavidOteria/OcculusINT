from pathlib import Path

def build_outfile(input_csv: str | Path, suffix: str) -> Path:
    """
    Convert *whatever.csv* → <base>_<suffix>.csv

    Rule:
        - take the stem (filename without extension)
        - drop its *last* “_chunk”   →  'bnp_domains_resolved' ➜ 'bnp_domains'
        - append '_<suffix>.csv'     →  'bnp_domains_vuln.csv'

    Examples
    --------
    >>> build_outfile('bnp_domains_resolved.csv', 'vuln')
    PosixPath('bnp_domains_vuln.csv')

    >>> build_outfile('targets/acme_list.csv', 'score')
    PosixPath('targets/acme_list_score.csv')
    """
    p = Path(input_csv)
    parts = p.stem.split("_")
    base = "_".join(parts[:-1]) if len(parts) > 1 else parts[0]
    return p.with_name(f"{base}_{suffix}.csv")