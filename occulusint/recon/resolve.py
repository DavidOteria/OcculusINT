# occulusint/recon/resolve.py

import socket
from typing import List, Dict


def resolve_domains(domains: List[str]) -> Dict[str, str]:
    """
    Resolve a list of domains to their IP addresses.

    :param domains: List of subdomains
    :return: Dictionary {domain: ip}
    """
    resolved = {}

    for domain in domains:
        try:
            ip = socket.gethostbyname(domain)
            resolved[domain] = ip
        except Exception as e:
            print(f"[!] Could not resolve {domain}: {e}")

    return resolved
