from sub3enum.engines.crtsh import CrtShEngine
from sub3enum.engines.brute import BruteEngine
from typing import List

class SubdomainsEnumerator: 
    """
    Wrapper around multiple Sub3num engines to enumerate subdomains for a given domain.
    """
    def __init__(self) -> None:
        self.engines = [
            CrtShEngine(), 
            BruteEngine()
        ]

    def enumerate(self, domain: str) -> List[str]: 
        """
        Run all subdomain engines and return a unique list of subdomains.
        
        :param domain: The root domain to enumerate
        :return: List of discovered subdomains
        """
        all_subdomains = set() 

        for engine in self.engines: 
            try:
                result =  engine.enumerate(domain)
                all_subdomains.update(result)
            except Exception as e: 
                print(f"[!] Engine {engine.__class__.__name__} failed: {e}")

        return sorted(all_subdomains)