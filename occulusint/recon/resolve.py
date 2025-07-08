import dns.resolver
import socket
from typing import List, Dict

def resolve_domains(domains: List[str]) -> Dict[str, str]:
    """
    Resolve a list of domain names to their IPv4 addresses using a public DNS resolver (Google's 8.8.8.8).

    :param domains: List of subdomains or fully qualified domain names (FQDNs).
    :return: Dictionary mapping each resolvable domain to its resolved IPv4 address.
    """
    resolved = {}
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8"]  # Use Google DNS
    resolver.timeout = 3
    resolver.lifetime = 5

    for domain in domains:
        try:
            answers = resolver.resolve(domain, "A")
            resolved[domain] = answers[0].to_text()
        except Exception as e:
            print(f"[!] Could not resolve {domain} using 8.8.8.8: {e}")

    return resolved


def is_reachable(ip: str, port: int = 443, timeout: float = 3.0) -> bool:
    """
    Check if a given IP address is reachable via a TCP connection on a specific port.

    :param ip: The IP address to test (e.g., '195.53.177.123').
    :param port: The TCP port to connect to (default: 443).
    :param timeout: Timeout in seconds for the connection attempt (default: 3.0).
    :return: True if the connection succeeds, False otherwise.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False
