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
        w = whois.whois(domain)
        org = w.get("org") or w.get("registrant_organization") or ""
        return org if isinstance(org, str) else org[0]
    except Exception:
        return ""


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


def detect_language(domain: str) -> str:
    """
    Quick check to infer if the default page language is French.
    """
    try:
        resp = requests.get(f"https://{domain}", timeout=5)
        text = resp.text.lower()
        if "connexion client" in text or "bnpparibas" in text:
            return "fr"
        return ""
    except Exception:
        return ""


def score_domain(domain: str, keyword: str) -> int:
    """
    Full scoring with network calls.

    :param domain: FQDN to score
    :param keyword: Target keyword (e.g. 'bnp')
    :return: Score between 0 and 100
    """
    d = domain.lower()
    kw = keyword.lower()
    score = 0

    # ===== Bonus principaux =====
    if d == f"{kw}.com" or d == f"{kw}.fr":
        score += 100
    if d.endswith((".com", ".fr", ".net")):
        score += 20
    if re.search(rf"(^|\W){re.escape(kw)}(\W|$)", d):
        score += 40
    for seg in [f"{kw}paribas", f"{kw}-paribas", "bnpparibas"]:
        if seg in d:
            score += 30
            break
    ext = tldextract.extract(d)
    if ext.subdomain and ext.domain.replace("-", "") == kw:
        score += 25
    if d.endswith((".fr", ".eu", ".be", ".lu")):
        score += 10
    for word in ["secure", "login", "client", "mobile", "intranet"]:
        if word in d:
            score += 10
            break
    if get_http_status(d) == 200:
        score += 15
    if "bnp" in get_whois_org(d).lower():
        score += 50
    if "bnpparibas" in get_soa_mname(d):
        score += 20
    if detect_language(d) == "fr":
        score += 10
    if get_domain_age(d) >= 5:
        score += 10

    # ===== Malus automatiques =====
    if re.search(rf"(^|\W)(dev|test|beta|staging|temp|demo)(\W|$)", d):
        score -= 30
    if d.endswith((".xyz", ".site", ".click", ".top", ".club")):
        score -= 20
    if len(d) > 40:
        score -= 15

    # Pas de DNS = score 0
    try:
        socket.gethostbyname(d)
    except Exception:
        return 0

    # Clamp final
    return max(0, min(100, score))


def static_score_domain(domain: str, keyword: str) -> int:
    """
    Fast score using only regex, length, TLD, and segments—no network calls.
    """
    d = domain.lower()
    kw = keyword.lower()
    score = 0

    if d == f"{kw}.com" or d == f"{kw}.fr":
        score += 100
    if d.endswith((".com", ".fr", ".net")):
        score += 20
    if re.search(rf"(^|\W){re.escape(kw)}(\W|$)", d):
        score += 40
    for seg in [f"{kw}paribas", f"{kw}-paribas", "bnpparibas"]:
        if seg in d:
            score += 30
            break
    ext = tldextract.extract(d)
    if ext.subdomain and ext.domain.replace("-", "") == kw:
        score += 25
    if len(d) < 20:
        score += 5
    elif len(d) > 40:
        score -= 10
    if re.search(rf"(^|\W)(dev|test|beta|staging|temp|demo)(\W|$)", d):
        score -= 30
    return max(0, min(100, score))


def score_domains_parallel(
    domains: List[str],
    keyword: str,
    max_workers: int = 10,
    show_progress: bool = False
) -> List[Tuple[str, int]]:
    """
    Score a list of domains in parallel using threads (network calls in score_domain).
    :param domains: list of FQDNs
    :param keyword: keyword for scoring
    :param max_workers: nombre de threads
    :param show_progress: si True, affiche une barre de progression
    :return: list of (domain, score) sorted by score desc
    """
    results: List[Tuple[str, int]] = []
    total = len(domains)
    completed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(score_domain, d, keyword): d for d in domains}

        if show_progress:
            # Initial empty bar
            bar_len = 40
            sys.stdout.write("Progress: [{}] 0% (0/{})".format(" " * bar_len, total))
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
                # reconstruction de la barre
                filled = int(bar_len * completed / total)
                bar = "=" * filled + " " * (bar_len - filled)
                percent = int(100 * completed / total)
                sys.stdout.write(
                    f"\rProgress: [{bar}] {percent}% ({completed}/{total})"
                )
                sys.stdout.flush()

        if show_progress:
            sys.stdout.write("\n")

    return sorted(results, key=lambda x: x[1], reverse=True)


def filter_and_score(domains: List[str], keyword: str, threshold: int = 50) -> List[Tuple[str, int]]:
    """
    Legacy: score all domains (slow) and filter by threshold.
    """
    scored: Dict[str, int] = {d: score_domain(d, keyword) for d in domains}
    filtered = [(d, s) for d, s in scored.items() if s >= threshold]
    return sorted(filtered, key=lambda x: x[1], reverse=True)


def is_subdomain(domain: str) -> bool:
    """
    Determine if a domain is a true subdomain (excluding 'www.domain.tld').

    :param domain: FQDN to evaluate
    :return: True if it's a subdomain, False otherwise
    """
    parts = domain.split(".")
    if len(parts) <= 2:
        return False
    if len(parts) == 3 and parts[0] == "www":
        return False
    return True
