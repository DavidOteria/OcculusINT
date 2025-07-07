"""Utility for caching and looking up CVSS scores from the NVD JSON feeds.

Highlights
~~~~~~~~~~
* Downloads **`nvdcve‑1.1‑recent.json.gz`** (≈ 10–15 MB) – last 8 days of CVE –
  which is enough for most weekly scans.  A full historical feed is 80 MB and
  can be enabled by setting ``FEED = "all"``.
* Keeps a pickled mapping ``cve → cvss_base_score`` under ``.cache/nvd``.
* Auto‑refreshes once a week.  You can force an update by calling
  ``update_cache(force=True)``.
"""

from __future__ import annotations

import datetime as _dt
import gzip as _gzip
import json as _json
import pickle as _pkl
import re as _re
import urllib.request as _url
from pathlib import Path
from typing import Dict, Optional

CACHE_DIR = Path(".cache/nvd")
CACHE_DIR.mkdir(parents=True, exist_ok=True)

FEED = "recent"  # "recent" (8 days) or "modified" (24 h) or "all"
BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/"
FEED_URL = f"{BASE_URL}nvdcve-1.1-{FEED}.json.gz"
PICKLE_PATH = CACHE_DIR / f"cvss_map_{FEED}.pkl"
MAX_AGE_DAYS = 7

_CVE_RE = _re.compile(r"CVE-\d{4}-\d{4,}")


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _download_feed() -> Dict[str, float]:
    """Download and parse the NVD feed – returns mapping CVE → CVSS float."""
    print(f"[*] Downloading NVD {FEED} feed …")
    with _url.urlopen(FEED_URL) as resp, _gzip.GzipFile(fileobj=resp) as gz:
        data = _json.load(gz)

    out: Dict[str, float] = {}
    for item in data["CVE_Items"]:
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        metrics = item.get("impact", {})
        score = None
        # Prefer CVSS v3.x
        if "baseMetricV3" in metrics:
            score = metrics["baseMetricV3"]["cvssV3"]["baseScore"]
        elif "baseMetricV2" in metrics:
            score = metrics["baseMetricV2"]["cvssV2"]["baseScore"]
        if score is not None:
            out[cve_id] = float(score)
    return out


def _is_cache_fresh() -> bool:
    if not PICKLE_PATH.exists():
        return False
    age = _dt.datetime.utcnow() - _dt.datetime.utcfromtimestamp(PICKLE_PATH.stat().st_mtime)
    return age.days < MAX_AGE_DAYS


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

_cvss_map: Optional[Dict[str, float]] = None


def load_cache(force: bool = False) -> Dict[str, float]:
    """Load CVSS map into memory (downloading if necessary)."""
    global _cvss_map
    if _cvss_map is not None and not force:
        return _cvss_map

    if force or not _is_cache_fresh():
        try:
            mapping = _download_feed()
            PICKLE_PATH.write_bytes(_pkl.dumps(mapping))
        except Exception as exc:
            # If download fails but pickle exists → use stale data; otherwise re‑raise
            if PICKLE_PATH.exists():
                print(f"[!] NVD download failed ({exc}); using stale cache")
            else:
                raise
    if _cvss_map is None or force:
        _cvss_map = _pkl.loads(PICKLE_PATH.read_bytes())
    return _cvss_map


def get_cvss(cve_id: str) -> Optional[float]:
    """Return the base CVSS score for *cve_id* or None if unknown."""
    if not _CVE_RE.fullmatch(cve_id):
        return None
    mapping = load_cache()
    return mapping.get(cve_id)
