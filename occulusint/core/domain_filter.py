# occulusint/core/domain_filter.py

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

def score_domain(domain: str, keywords: List[str]) -> int:
    """
    Full scoring with network calls.

    :param domain: FQDN to score
    :param keywords: List of target keywords
    :return: Score between 0 and 100
    """
    d = domain.lower()
    kws = [kw.lower() for kw in keywords]
    score = 0

    # ===== Bonus principaux =====
    # Exact root match (.com / .fr)
    for kw in kws:
        if d == f"{kw}.com" or d == f"{kw}.fr":
            score += 100
            break

    # Trusted TLDs
    if d.endswith((".com", ".fr", ".net")):
        score += 20

    # Keyword as whole word
    for kw in kws:
        if re.search(rf"(^|\W){re.escape(kw)}(\W|$)", d):
            score += 40
            break

    # Legitimate subdomain pattern (e.g. api.<keyword>.com)
    ext = tldextract.extract(d)
    for kw in kws:
        if ext.subdomain and ext.domain.replace("-", "") == kw:
            score += 25
            break

    # Geographic suffix
    if d.endswith((".fr", ".eu", ".be", ".lu")):
        score += 10

    # Business keywords
    for word in ["secure", "login", "client", "mobile", "intranet"]:
        if word in d:
            score += 10
            break

    # HTTP alive?
    if get_http_status(d) == 200:
        score += 15

    # WHOIS org contains keyword?
    org = get_whois_org(d).lower()
    for kw in kws:
        if kw in org:
            score += 50
            break

    # SOA MNAME contains keyword?
    soa = get_soa_mname(d).lower()
    for kw in kws:
        if kw in soa:
            score += 20
            break

    # Language detection (French)
    if detect_language(d, kws) == "fr":
        score += 10

    # Domain age ≥ 5 ans
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
