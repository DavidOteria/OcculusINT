import json
import pathlib
import time
import requests
from shodan import APIError, Shodan
from typing import Any, Dict, Optional

CACHE_DIR = pathlib.Path(".cache/shodan")
CACHE_DIR.mkdir(parents=True, exist_ok=True)
RATE_LIMIT = 1.1  # seconds


def extract_nested(source: Dict[str, Any], dotted_path: str) -> Optional[Any]:
    """
    Walk a dotted *path* (e.g. 'ssl.cert.subject.CN') inside nested dicts.

    :param src: Shodan banner (dict)
    :param path: dotted path to extract
    :return: value or None if any key is missing
    """
    parts = dotted_path.split(".")
    current = source
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


def load_cache(ip: str) -> Optional[Dict[str, Any]]:
    """
    Load JSON for *ip* from local cache.

    :param ip: IPv4/IPv6 as string
    :return: cached dict or None
    """
    path = CACHE_DIR / f"{ip}.json"
    if path.exists():
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            path.unlink(missing_ok=True)
    return None


def save_cache(ip: str, data: Dict[str, Any]) -> None:
    """
    Save raw Shodan JSON to cache.

    :param ip: IPv4/IPv6 as string
    :param data: JSON dict returned by Shodan
    :return: None
    """
    (CACHE_DIR / f"{ip}.json").write_text(json.dumps(data))


def query_shodan(api: Shodan, ip: str) -> Dict[str, Any]:
    """
    Query Shodan Host API with cache & rate-limit.

    :param api: Shodan() instance
    :param ip: IP address
    :return: JSON dict for that host
    """
    cached = load_cache(ip)
    if cached:
        return cached

    data = api.host(ip, history=False)
    save_cache(ip, data)
    time.sleep(RATE_LIMIT)
    return data


def query_internetdb(ip: str) -> Dict[str, Any]:
    """
    Fallback to InternetDB (free). Ports + vulns only.

    :param ip: IP address
    :return: JSON-like dict compatible with Shodan structure
    """
    url = f"https://internetdb.shodan.io/{ip}"
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    raw = resp.json()
    return {
        "ip_str": ip,
        "ports": raw.get("ports", []),
        "vulns": raw.get("vulns", []),
        "data": [],
    }