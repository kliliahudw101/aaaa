import socket
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.config import G, safe_print, t, Fore, Style
from core.network import resolve_host

SUBDOMAIN_PREFIXES = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "api", "dev", "staging",
    "test", "admin", "portal", "vpn", "remote", "blog", "forum", "shop",
    "store", "cdn", "static", "media", "images", "img", "assets", "css",
    "js", "app", "m", "mobile", "web", "cloud", "s3", "db", "database",
    "mysql", "postgres", "redis", "elastic", "git", "github", "gitlab",
    "ci", "jenkins", "build", "deploy", "monitor", "grafana", "prometheus",
    "log", "logs", "syslog", "metrics", "status", "health", "ping",
    "backup", "old", "new", "beta", "alpha", "demo", "sandbox", "stage",
    "prod", "production", "internal", "intranet", "wiki", "docs", "doc",
    "help", "support", "crm", "erp", "hr", "auth", "sso", "oauth",
    "login", "signin", "signup", "register", "accounts", "billing",
    "payment", "pay", "checkout", "cart", "order", "tracking", "notify",
    "notification", "email", "newsletter", "news", "feed", "rss", "api2",
    "v2", "v3", "rest", "graphql", "soap", "ws", "wss", "tcp", "udp",
]

def run_dns_enumeration(target_host):
    """Run comprehensive DNS enumeration and subdomain discovery."""
    safe_print(f"  {Fore.CYAN}[*] DNS: Starting enumeration for {target_host}...{Style.RESET_ALL}")

    found_subdomains = []

    # 1. Threaded brute force
    def check_subdomain(prefix):
        fqdn = f"{prefix}.{target_host}"
        try:
            ip = socket.gethostbyname(fqdn)
            return (fqdn, ip)
        except socket.gaierror:
            return None

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(check_subdomain, p) for p in SUBDOMAIN_PREFIXES]
        for future in as_completed(futures):
            res = future.result()
            if res:
                found_subdomains.append(res)

    # 2. Integrate external tools if available
    subfinder = shutil.which("subfinder")
    if subfinder:
        safe_print(f"  {Fore.CYAN}[*] DNS: Running subfinder...{Style.RESET_ALL}")
        try:
            result = subprocess.run([subfinder, "-d", target_host, "-silent"],
                                   capture_output=True, text=True, timeout=120)
            for sub in result.stdout.splitlines():
                if sub and sub not in [s[0] for s in found_subdomains]:
                    ip = resolve_host(sub)
                    found_subdomains.append((sub, ip))
        except Exception as e:
            if G.logger:
                G.logger.error(f"subfinder error: {e}")

    # 3. Check common DNS records
    dns_records = {}
    dig = shutil.which("dig")
    if dig:
        for rtype in ["A", "MX", "NS", "TXT"]:
            try:
                res = subprocess.run([dig, rtype, target_host, "+short"],
                                    capture_output=True, text=True, timeout=10)
                dns_records[rtype] = res.stdout.strip().splitlines()
            except Exception:
                dns_records[rtype] = []

    return {
        "subdomains": sorted(found_subdomains),
        "records": dns_records
    }
