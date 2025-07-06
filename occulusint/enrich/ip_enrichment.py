import requests
from ipwhois import IPWhois
from typing import Dict, Tuple

def get_asn_info(ip: str) -> Tuple[str, str]:
    """
    Retrieve ASN and network name for a given IP using IPWhois.

    :param ip: IP address string
    :return: (asn, network_name)
    """
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        asn = result.get("asn", "")
        netname = result.get("network", {}).get("name", "")
        return asn, netname
    except Exception:
        return "", ""

def get_geolocation(ip: str) -> Dict[str, str]:
    """
    Retrieve geolocation information for an IP via the public ip-api.com.

    :param ip: IP address string
    :return: dict with keys 'country', 'region', 'city'
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        if data.get("status") != "success":
            return {}
        return {
            "country": data.get("country", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", "")
        }
    except Exception:
        return {}

def detect_cloud_provider(asn: str, network_name: str) -> str:
    """
    Determine cloud provider based on ASN or network name.

    :param asn: Autonomous System Number string (e.g. "AS16509")
    :param network_name: netname from the RDAP lookup
    :return: one of 'AWS', 'GCP', 'Azure', 'OVH', or 'Other'
    """
    s = f"{asn} {network_name}".lower()
    if "amazon" in s or "aws" in s:
        return "AWS"
    if "google" in s or "goog" in s:
        return "GCP"
    if "microsoft" in s or "azure" in s:
        return "Azure"
    if "ovh" in s:
        return "OVH"
    return "Other"