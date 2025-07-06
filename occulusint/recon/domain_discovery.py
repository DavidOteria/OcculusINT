import requests
import re
from typing import List, Set

# occulusint/recon/domain_discovery.py

import requests
import re
from typing import List, Set


def discover_domains_from_crtsh(keyword: str) -> List[str]:
    """
    Use crt.sh to discover domain names containing the keyword.
    
    :param keyword: Search keyword (e.g. 'bnp')
    :return: List of unique domain names
    """
    url = f"https://crt.sh/?q=%25{keyword}%25&output=json"

    try:
        response = requests.get(url, timeout=30)
        if response.status_code != 200:
            print(f"[!] crt.sh returned status {response.status_code}")
            return []

        data = response.json()
        domains: Set[str] = set()

        for entry in data:
            name_value = entry.get("name_value", "")
            found = re.findall(r"[\w.-]+\.\w+", name_value)
            domains.update(found)

        return sorted(domains)

    except Exception as e:
        print(f"[!] Error querying crt.sh: {e}")
        return []
