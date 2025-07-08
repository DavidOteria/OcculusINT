import sys
import re
import socket
import requests
import whois
import dns.resolver
import tldextract
from datetime import datetime
from typing import List, Tuple, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_http_status(domain: str) -> int:
    """
    Return the HTTP status code for a given domain using a HEAD request over HTTPS.

    :param domain: The domain name to test (e.g., 'example.com').
    :return: The HTTP status code (e.g., 200, 301, 404), or 0 if the request fails.
    """
    try:
        resp = requests.head(f"https://{domain}", timeout=5, allow_redirects=True)
        return resp.status_code
    except Exception:
        return 0

def get_whois_org(domain: str) -> str:
    """
    Retrieve the registrant organization from the WHOIS record of a domain.

    :param domain: The domain name to query (e.g., 'example.com').
    :return: The organization name as a lowercase string, or an empty string if unavailable.
    """
    try:
        info = whois.whois(domain)
        org = info.get("org") or ""
        return str(org).strip()
    except Exception:
        return ""

def get_soa_mname(domain: str) -> str:
    """
    Retrieve the MNAME (primary nameserver) field from the SOA record of a domain.

    :param domain: The domain name to query (e.g., 'example.com').
    :return: The MNAME value as a string (without trailing dot), or an empty string if not found.
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
    Estimate the domain's age in years, based on the WHOIS creation_date field.

    :param domain: The domain name to query (e.g., 'example.com').
    :return: Domain age in full years. Returns 0 if the creation date is unavailable or invalid.
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
    """
    Extract the base domain (e.g., 'example.com') from any FQDN or subdomain.

    :param domain: A full domain or subdomain (e.g., 'api.example.com').
    :return: The base domain (e.g., 'example.com').
    """
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}"

def is_root_domain(fqdn: str) -> bool:
    """
    Check if a FQDN is the root/base domain.

    :param fqdn: The fully qualified domain name to test.
    :return: True if it matches its base domain (e.g., 'example.com').
    """
    return fqdn == get_base_domain(fqdn)

def is_subdomain(fqdn: str) -> bool:
    """
    Determine if a FQDN is a subdomain (i.e., not equal to its base domain).

    :param fqdn: The fully qualified domain name to test.
    :return: True if it's a subdomain (e.g., 'api.example.com').
    """
    return not is_root_domain(fqdn)

def has_https(domain: str) -> bool:
    """
    Return True if HTTPS is available and responds correctly.

    :param fqdn: The fully qualified domain name to test. 
    :return: True if it's https is available 
    """
    try:
        r = requests.head(f"https://{domain}", timeout=5, allow_redirects=True)
        return r.status_code < 400
    except Exception:
        return False

def score_domain(domain: str, keywords: List[str]) -> int:
    """
    Compute a heuristic score indicating the risk or interest level of a domain.

    Criteria:
    - +30 if the domain or subdomain contains suspicious or sensitive keywords
    - +15 if HTTPS is available (suggests real infra)
    - +20 if the domain is a subdomain (more attack surface)
    - +10 if domain contains digits (e.g., staging1, test2)
    - +5  if domain length is unusually long

    :param domain: Domain or subdomain to evaluate.
    :param keywords: List of keywords considered sensitive or business-related.
    :return: Integer score (higher = more interesting/suspicious)
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
    """
    Map a numeric risk score to a qualitative label.

    :param score: An integer score (typically between 0 and 100).
    :return: One of the labels: "critique", "suspect", "surveiller", or "ok".
    """
    if score >= 80:
        return "critique"
    elif score >= 60:
        return "suspect"
    elif score >= 40:
        return "surveiller"
    else:
        return "ok"
