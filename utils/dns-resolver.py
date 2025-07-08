import dns.resolver

def resolve_domain_public(d: str) -> str:
    """
    Resolve a domain using a public DNS resolver (e.g., 8.8.8.8).
    Returns the first A record IP, or "" on failure.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8"]  # or 1.1.1.1 (Cloudflare)
        answers = resolver.resolve(d, "A", lifetime=5)
        return answers[0].to_text()
    except Exception:
        return ""