import sys
import os
import urllib.parse
import datetime
from colorama import Fore, Style
from core.config import G, t, safe_print, setup_logging
from core.network import resolve_host
from core.ai_manager import AIManager
from core.osint import OSINTModule
from core.reporting import generate_report
from modules.recon import run_reconnaissance
from modules.dns import run_dns_enumeration
from modules.vuln import VulnerabilityScanner
from modules.cve import run_cve_analysis
from modules.fingerprint import run_fingerprint

def banner():
    print(Fore.CYAN + """
    ╔══════════════════════════════════════════════════════════════════╗
    ║         DEEP RECON Framework v5.0 (Modular & AI-Powered)        ║
    ║              Authorized Penetration Testing Only                 ║
    ║         فحص عميق - فريمورك استطلاع أمني متقدم                   ║
    ╚══════════════════════════════════════════════════════════════════╝
    """ + Style.RESET_ALL)

def main():
    os.system('clear' if os.name != 'nt' else 'cls')
    banner()

    # 1. Language and Authorization
    lang_choice = input("[?] Select Language (1: EN, 2: AR): ").strip()
    G.lang = "ar" if lang_choice == "2" else "en"

    auth_prompt = "[?] Do you have authorization to test this target? (Y/n): " if G.lang == "en" else "[?] هل لديك تصريح لاختبار هذا الهدف؟ (Y/n): "
    auth = input(auth_prompt).strip().lower()
    if auth == 'n':
        abort_msg = "[!] Scan aborted." if G.lang == "en" else "[!] تم إلغاء الفحص."
        print(abort_msg)
        sys.exit(0)

    # 2. Target Setup
    target_prompt = "[?] Enter target URL (e.g., https://example.com): " if G.lang == "en" else "[?] أدخل رابط الهدف (مثال: https://example.com): "
    target = input(target_prompt).strip()
    if not target.startswith("http"):
        target = "https://" + target

    parsed = urllib.parse.urlparse(target)
    G.target_url = target.rstrip("/")
    G.target_host = parsed.hostname

    # 3. AI Setup
    api_prompt = "[?] Enter OpenRouter API Key (optional for free models): " if G.lang == "en" else "[?] أدخل مفتاح OpenRouter API (اختياري للنماذج المجانية): "
    api_key = input(api_prompt).strip()
    ai = AIManager(api_key)

    # 4. Initialize Output
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    G.output_dir = f"reports/scan_{G.target_host}_{ts}"
    os.makedirs(G.output_dir, exist_ok=True)
    setup_logging(G.output_dir)

    all_results = {}

    try:
        # Phase 1: Recon & OSINT
        safe_print(f"\n{Fore.GREEN}[+] PHASE 1: Reconnaissance & OSINT{Style.RESET_ALL}")
        all_results["recon"] = run_reconnaissance(G.target_url)
        osint = OSINTModule(G.target_host)
        all_results["osint"] = osint.run_all()

        # Phase 2: DNS & Subdomains
        safe_print(f"\n{Fore.GREEN}[+] PHASE 2: DNS & Subdomain Discovery{Style.RESET_ALL}")
        all_results["dns"] = run_dns_enumeration(G.target_host)

        # Phase 3: Fingerprinting & CVE Matching
        safe_print(f"\n{Fore.GREEN}[+] PHASE 3: Technology Detection & CVE Matching{Style.RESET_ALL}")
        all_results["fingerprint"] = run_fingerprint(G.target_url)
        all_results["cves"] = run_cve_analysis(all_results["fingerprint"])

        # Phase 4: Vulnerability Scanning (Deep XSS, CORS)
        safe_print(f"\n{Fore.GREEN}[+] PHASE 4: Vulnerability Scanning{Style.RESET_ALL}")
        vuln_scanner = VulnerabilityScanner(G.target_url)
        all_results["vulnerabilities"] = vuln_scanner.run_all()

        # Phase 5: AI Analysis
        safe_print(f"\n{Fore.GREEN}[+] PHASE 5: AI-Powered Strategic Analysis{Style.RESET_ALL}")
        scan_summary = str(all_results)[:15000] # Increased limit for AI
        all_results["ai_analysis"] = ai.route_task("strategic", scan_summary)

        # Phase 6: Generate PoC via AI for confirmed vulns
        if all_results["vulnerabilities"]:
            safe_print(f"\n{Fore.GREEN}[+] PHASE 6: AI-Powered Exploit Generation{Style.RESET_ALL}")
            vuln_details = str(all_results["vulnerabilities"])
            all_results["ai_exploits"] = ai.route_task("exploit", vuln_details)

        # Finalize
        report_path = generate_report(G.target_url, all_results)
        safe_print(f"\n{Fore.GREEN}[✓] SCAN COMPLETED SUCCESSFULLY!{Style.RESET_ALL}")
        safe_print(f"[+] Final Report: {report_path}")

    except KeyboardInterrupt:
        safe_print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)

if __name__ == "__main__":
    main()
