import re
import urllib.parse
import requests
from bs4 import BeautifulSoup
from core.config import G, safe_print, t, Fore, Style
from core.network import http_get, http_request

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><svg onload=alert(1)>',
    '"><details open ontoggle=alert(1)>',
    '"><marquee onstart=alert(1)>',
    '"><video><source onerror=alert(1)>',
    '"><audio src=x onerror=alert(1)>',
    '"><iframe src=javascript:alert(1)>',
]

class VulnerabilityScanner:
    """Deep XSS and web vulnerability scanner."""

    def __init__(self, target_url):
        self.target_url = target_url
        self.base_url = target_url.rstrip("/")
        self.found_vulns = []
        self.forms = []
        self.params = []

    def crawl_inputs(self):
        """Extract all possible input vectors (forms and parameters)."""
        safe_print(f"  {Fore.CYAN}[*] VULN: Crawling {self.target_url} for input vectors...{Style.RESET_ALL}")
        resp = http_get(self.target_url)
        if not resp:
            return

        soup = BeautifulSoup(resp.text, 'html.parser')

        # 1. Forms
        for form in soup.find_all('form'):
            action = form.get('action')
            method = form.get('method', 'GET').upper()
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                if name:
                    inputs.append({"name": name, "type": input_tag.get('type', 'text')})
            self.forms.append({"action": action, "method": method, "inputs": inputs})

        # 2. URL parameters
        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)
        for p in params:
            self.params.append(p)

    def test_xss(self):
        """Test discovered vectors for reflected XSS."""
        safe_print(f"  {Fore.CYAN}[*] VULN: Testing {len(self.forms)} forms and {len(self.params)} parameters for XSS...{Style.RESET_ALL}")

        # Test URL parameters
        for p in self.params:
            for payload in XSS_PAYLOADS:
                test_url = f"{self.base_url}/?{p}={urllib.parse.quote(payload)}"
                resp = http_get(test_url, timeout=5)
                if resp and payload in resp.text:
                    self.found_vulns.append({
                        "type": "XSS",
                        "method": "GET",
                        "url": test_url,
                        "parameter": p,
                        "payload": payload,
                        "description": f"Reflected XSS via URL parameter '{p}'",
                        "remediation": "Implement proper input sanitization and output encoding."
                    })
                    break

        # Test Forms
        for form in self.forms:
            action = form.get('action')
            full_action = urllib.parse.urljoin(self.target_url, action) if action else self.target_url
            method = form.get('method', 'GET')

            for payload in XSS_PAYLOADS:
                data = {}
                for inp in form['inputs']:
                    data[inp['name']] = payload

                resp = http_request(method, full_action, timeout=5, data=data if method == 'POST' else None, params=data if method == 'GET' else None)
                if resp and payload in resp.text:
                    self.found_vulns.append({
                        "type": "XSS",
                        "method": method,
                        "url": full_action,
                        "form_inputs": [inp['name'] for inp in form['inputs']],
                        "payload": payload,
                        "description": f"XSS via form inputs in {full_action}",
                        "remediation": "Use context-aware output encoding."
                    })
                    break

    def test_cors(self):
        """Check for CORS misconfigurations."""
        safe_print(f"  {Fore.CYAN}[*] VULN: Testing CORS configuration...{Style.RESET_ALL}")
        origins = ["https://evil.com", "null"]
        for origin in origins:
            resp = http_get(self.base_url, headers={"Origin": origin}, timeout=5)
            if resp:
                acao = resp.headers.get("Access-Control-Allow-Origin")
                acac = resp.headers.get("Access-Control-Allow-Credentials")
                if acao == "*" or acao == origin:
                    self.found_vulns.append({
                        "type": "CORS Misconfiguration",
                        "origin": origin,
                        "ACAO": acao,
                        "ACAC": acac,
                        "severity": "HIGH" if acac == "true" else "MEDIUM",
                        "description": f"CORS reflects origin '{origin}' with credentials allowed." if acac == "true" else f"CORS allows wildcard or reflected origin '{origin}'."
                    })
                    break

    def run_all(self):
        self.crawl_inputs()
        self.test_xss()
        self.test_cors()
        return self.found_vulns
