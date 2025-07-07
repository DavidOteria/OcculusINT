# occulusint/core/domain_filter.py

import sys
import re
import socket
import requests
import whois
import dns.resolver
import tldextract
import tldextract
from datetime import datetime
from typing import List, Tuple, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_http_status(domain: str) -> int:
    """
    Return HTTP status code for a given domain using a HEAD request.
    """
    try:
        resp = requests.head(f"https://{domain}", timeout=5, allow_redirects=True)
        return resp.status_code
    except Exception:
        return 0

def get_whois_org(domain: str) -> str:
    """
    Return the registrant organization from WHOIS, or empty string if unavailable.
    """
    try:
        org = get_whois_org(d).lower()
        if not any(kw in org for kw in kws):
            score += 20
    except Exception:
        score += 10  # on considère que l'absence d'infos WHOIS est suspecte

def get_soa_mname(domain: str) -> str:
    """
    Return the MNAME (primary nameserver) field from the domain's SOA record.
    """
    try:
        answers = dns.resolver.resolve(domain, "SOA", lifetime=5)
        return str(answers[0].mname).rstrip(".")
    except Exception:
        return ""

def get_domain_age(domain: str) -> int:
    """
    Return the age of the domain in years, based on WHOIS creation_date.
    """
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if isinstance(created, datetime):
            return (datetime.now() - created).days // 365
        return 0
    except Exception:
        return 0

def detect_language(domain: str, keywords: List[str]) -> str:
    """
    Quick check to infer if the default page language matches any keyword.
    """
    try:
        resp = requests.get(f"https://{domain}", timeout=5)
        text = resp.text.lower()
        for kw in keywords:
            if kw.lower() in text:
                return "fr"
        return ""
    except Exception:
        return ""
    
def get_base_domain(domain: str) -> str:
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}"

def is_root_domain(fqdn: str) -> bool:
    return fqdn == get_base_domain(fqdn)

def is_subdomain(fqdn: str) -> bool:
    """
    Determine if a FQDN is a true subdomain (not equal to its base domain).
    Example:
        bnp.fr               → root domain
        www.bnp.fr           → subdomain
        api.client.bnp.fr    → subdomain
    """
    return not is_root_domain(fqdn)

def has_https(domain: str) -> bool:
    """
    Return True if HTTPS is available and responds correctly.
    """
    try:
        r = requests.head(f"https://{domain}", timeout=5, allow_redirects=True)
        return r.status_code < 400
    except Exception:
        return False

def score_domain(domain: str, keywords: List[str]) -> int:
    """
    Return a risk-based score indicating how much the domain should be reviewed.
    Higher score = more suspicious or needs admin attention.
    """
    d = domain.lower()
    kws = [kw.lower() for kw in keywords]
    score = 0
    ext = tldextract.extract(d)

    # Absence de HTTPS = hautement suspect
    if not has_https(d):
        score += 30

    # TLD douteux
    if d.endswith((".xyz", ".top", ".click", ".site", ".club")):
        score += 40

    # Sous-domaine technique / potentiellement sensible
    if re.search(r"(dev|test|beta|vpn|backup|api|secure|auth|admin)", d):
        score += 25

    # Mots sensibles d’interface utilisateur
    for word in ["login", "client", "mobile", "intranet", "account", "portal"]:
        if word in d:
            score += 25
            break

    # Domaine actif HTTP mais WHOIS non corrélé
    if get_http_status(d) == 200:
        org = get_whois_org(d).lower()
        if not any(kw in org for kw in kws):
            score += 20

    # SOA distant ou inconnu
    soa = get_soa_mname(d).lower()
    if soa and not any(kw in soa for kw in kws):
        score += 10

    # Page non francophone (si ciblage FR)
    if detect_language(d, kws) != "fr":
        score += 5

    # Nom trop long
    if len(d) > 40:
        score += 10

    # DNS inexistant → score nul
    try:
        socket.gethostbyname(d)
    except Exception:
        return 0

    return min(100, score)


def score_domains_parallel(
    domains: List[str],
    keywords: List[str],
    max_workers: int = 10,
    show_progress: bool = False
) -> List[Tuple[str, int]]:
    """
    Score a list of domains in parallel using threads (network calls in score_domain).

    :param domains: list of FQDNs
    :param keywords: list of target keywords
    :param max_workers: number of threads
    :param show_progress: if True, display a progress bar
    :return: list of (domain, score) sorted by score desc
    """
    total = len(domains)
    completed = 0
    results: List[Tuple[str, int]] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(score_domain, d, keywords): d for d in domains}

        if show_progress:
            bar_len = 40
            sys.stdout.write(f"Progress: [{' ' * bar_len}] 0% (0/{total})")
            sys.stdout.flush()

        for future in as_completed(future_map):
            d = future_map[future]
            try:
                s = future.result()
            except Exception:
                s = 0
            results.append((d, s))

            if show_progress:
                completed += 1
                filled = int(bar_len * completed / total)
                bar = "=" * filled + " " * (bar_len - filled)
                pct = int(100 * completed / total)
                sys.stdout.write(f"\rProgress: [{bar}] {pct}% ({completed}/{total})")
                sys.stdout.flush()

        if show_progress:
            sys.stdout.write("\n")

    return sorted(results, key=lambda x: x[1], reverse=True)

def score_to_label(score: int) -> str:
    if score >= 80:
        return "critique"
    elif score >= 60:
        return "suspect"
    elif score >= 40:
        return "surveiller"
    else:
        return "ok"
