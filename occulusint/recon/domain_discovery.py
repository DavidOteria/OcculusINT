import requests
import re
import time
from typing import List, Set

def discover_domains_from_crtsh(keywords: List[str]) -> List[str]:
    """
    Query crt.sh for certificate transparency logs using a list of keywords.
    Returns a list of unique FQDNs (fully qualified domain names) found.

    :param keywords: A list of keywords to search for (e.g., ['bxx', 'bxxxxxx-xxs', 'bxx-xf']).
                     Each keyword will be used to search crt.sh individually.
    :return: A sorted list of unique domain names (FQDNs) matched by crt.sh queries.
    """

    headers = {"User-Agent": "Mozilla/5.0"}
    all_domains: Set[str] = set()

    for keyword in keywords:
        url = f"https://crt.sh/?q=%25{keyword}%25&output=json"
        print(f"[~] Querying crt.sh for: {keyword}")
        try:
            response = requests.get(url, timeout=30, headers=headers)
            if response.status_code != 200:
                print(f"[!] crt.sh returned status {response.status_code} for {keyword}")
                continue

            try:
                data = response.json()
            except Exception:
                print(f"[!] Invalid JSON for {keyword}")
                continue

            for entry in data:
                name_value = entry.get("name_value", "")
                found = re.findall(r"[\w.-]+\.\w+", name_value)
                all_domains.update(found)

        except Exception as e:
            print(f"[!] Error querying crt.sh for {keyword}: {e}")

        time.sleep(1.5)  # gentle pacing between requests

    return sorted(all_domains)
