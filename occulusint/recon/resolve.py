import dns.resolver
from typing import List, Dict

def resolve_domains(domains: List[str]) -> Dict[str, str]:
    """
    Resolve a list of domains to their IP addresses using a public DNS resolver (8.8.8.8).

    :param domains: List of subdomains or FQDNs
    :return: Dictionary {domain: ip}
    """
    resolved = {}
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8"]  # Use Google's DNS
    resolver.timeout = 3
    resolver.lifetime = 5

    for domain in domains:
        try:
            answers = resolver.resolve(domain, "A")
            resolved[domain] = answers[0].to_text()
        except Exception as e:
            print(f"[!] Could not resolve {domain} using 8.8.8.8: {e}")

    return resolved