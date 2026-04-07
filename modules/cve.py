import requests
import json
import re
import os
from core.config import G, safe_print, t, Fore, Style

def query_nvd(tech_name, limit=10):
    """Query NVD API for CVEs matching a technology name."""
    safe_print(f"  {Fore.CYAN}[*] CVE: Querying NVD for {tech_name}...{Style.RESET_ALL}")
    try:
        nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"keywordSearch": tech_name, "resultsPerPage": limit}
        # Fixed insecure API call (removed verify=False for NVD)
        resp = requests.get(nvd_url, params=params, timeout=20,
                            headers={"User-Agent": "DeepRecon-Scanner/5.0"},
                            proxies=G.proxies)
        if resp.status_code == 200:
            data = resp.json()
            results = []
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id")
                desc = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                metrics = cve.get("metrics", {})
                severity = "N/A"
                score = "N/A"
                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0].get("cvssData", {})
                    severity = cvss.get("baseSeverity", "N/A")
                    score = cvss.get("baseScore", "N/A")
                results.append({"cve_id": cve_id, "description": desc, "severity": severity, "score": score, "tech": tech_name})
            return results
    except Exception as e:
        if G.logger:
            G.logger.error(f"NVD query error for {tech_name}: {e}")
    return []

def search_exploits_github(cve_id):
    """Search GitHub for PoCs of a specific CVE."""
    safe_print(f"  {Fore.CYAN}[*] CVE: Searching GitHub for {cve_id} PoCs...{Style.RESET_ALL}")
    try:
        search_url = f"https://api.github.com/search/repositories?q={cve_id}+exploit"
        # Fixed insecure API call (removed verify=False for GitHub)
        resp = requests.get(search_url, timeout=15, proxies=G.proxies)
        if resp.status_code == 200:
            data = resp.json()
            return [{"name": repo["full_name"], "url": repo["html_url"], "description": repo["description"]} for repo in data.get("items", [])[:5]]
    except Exception as e:
        if G.logger:
            G.logger.error(f"GitHub search error for {cve_id}: {e}")
    return []

def run_cve_analysis(detected_techs):
    """Analyze detected technologies and find matching CVEs and exploits."""
    all_cves = []
    for tech in detected_techs:
        cves = query_nvd(tech)
        for cve in cves:
            cve["exploits"] = search_exploits_github(cve["cve_id"])
            all_cves.append(cve)
    return all_cves
