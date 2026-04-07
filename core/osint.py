import re
import requests
import json
import logging
from core.config import G, safe_print, t
from core.network import http_get

class OSINTModule:
    """Collect public security intelligence without requiring API keys."""

    def __init__(self, target_host):
        self.target_host = target_host
        self.output = []

    def fetch_crt_sh(self):
        """Query certificate transparency."""
        safe_print(f"  {Fore.CYAN}[*] OSINT: Querying crt.sh...{Style.RESET_ALL}")
        try:
            cert_url = f"https://crt.sh/?q=%.{self.target_host}&output=json"
            cert_resp = requests.get(cert_url, timeout=20, verify=False, proxies=G.proxies)
            if cert_resp and cert_resp.status_code == 200:
                cert_data = cert_resp.json()
                seen = set()
                results = []
                for cert in cert_data:
                    name = cert.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip()
                        if n and n not in seen:
                            seen.add(n)
                            results.append(n)
                return sorted(results)
        except Exception as e:
            if G.logger:
                G.logger.error(f"crt.sh error: {e}")
        return []

    def fetch_wayback_urls(self, limit=100):
        """Query Wayback Machine for archived URLs."""
        safe_print(f"  {Fore.CYAN}[*] OSINT: Querying Wayback Machine...{Style.RESET_ALL}")
        try:
            wayback_api = f"http://web.archive.org/cdx/search/cdx?url={self.target_host}/*&output=json&limit={limit}&fl=original"
            wb_resp = requests.get(wayback_api, timeout=20, verify=False, proxies=G.proxies)
            if wb_resp and wb_resp.status_code == 200:
                wb_data = wb_resp.json()
                if len(wb_data) > 1:
                    return sorted(set(row[0] for row in wb_data[1:]))
        except Exception as e:
            if G.logger:
                G.logger.error(f"Wayback error: {e}")
        return []

    def fetch_shodan_public(self, ip):
        """Search Shodan for the IP (using public view)."""
        # Note: Shodan public view often requires an API key, so we'll skip for now or use alternative public search
        return "Shodan public search requires an API key for meaningful results."

    def run_all(self):
        findings = {
            "subdomains": self.fetch_crt_sh(),
            "archived_urls": self.fetch_wayback_urls()
        }
        return findings
