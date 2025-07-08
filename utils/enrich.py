from occulusint.enrich.ip_enrichment import (
    get_asn_info,
    get_geolocation,
    detect_cloud_provider
)

def enrich_record(row):
    """
    Enrich a single row with ASN, geolocation and cloud provider.
    Input: {'domain': ..., 'ip': ...}
    Output: enriched dict with keys:
        domain, ip, asn, network_name, country, region, city, provider
    """
    domain = row["domain"]
    ip = row["ip"]
    asn, netname = get_asn_info(ip)
    geo = get_geolocation(ip)
    provider = detect_cloud_provider(asn, netname)
    return {
        "domain": domain,
        "ip": ip,
        "asn": asn,
        "network_name": netname,
        "country": geo.get("country", ""),
        "region": geo.get("region", ""),
        "city": geo.get("city", ""),
        "provider": provider
    }