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
    path = CACHE_DIR / f"{ip}.json"
    if path.exists():
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            path.unlink(missing_ok=True)
    return None


def save_cache(ip: str, data: Dict[str, Any]) -> None:
    (CACHE_DIR / f"{ip}.json").write_text(json.dumps(data))


def query_shodan(api: Shodan, ip: str) -> Dict[str, Any]:
    cached = load_cache(ip)
    if cached:
        return cached

    data = api.host(ip, history=False)
    save_cache(ip, data)
    time.sleep(RATE_LIMIT)
    return data


def query_internetdb(ip: str) -> Dict[str, Any]:
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
