import re
from core.config import G, safe_print, Fore, Style
from core.network import http_get

TECH_SIGNATURES = {
    "WordPress": [r"/wp-content/", r"/wp-includes/", r"wp-json", r"wordpress"],
    "Joomla": [r"/media/jui/", r"/components/com_", r"joomla"],
    "Drupal": [r"drupal", r"sites/all/themes", r"Drupal.settings"],
    "Moodle": [r"moodle", r"moodle/form", r"core/login", r"atto", r"tiny_mce"],
    "Laravel": [r"laravel_session", r"laravel_token", r"XSRF-TOKEN"],
    "Django": [r"csrfmiddlewaretoken", r"django"],
    "Express.js": [r"x-powered-by: express", r"express"],
    "React": [r"react", r"__NEXT_DATA__", r"next.js", r"_next"],
    "Vue.js": [r"vue", r"v-cloak", r"v-bind", r"vuejs"],
    "Angular": [r"ng-app", r"ng-version", r"angular", r"ng-content"],
    "Nginx": [r"server: nginx", r"nginx"],
    "Apache": [r"server: apache", r"apache", r"mod_"],
    "IIS": [r"server: microsoft-iis", r"x-aspnet", r"x-powered-by: asp.net"],
    "PHP": [r"x-powered-by: php", r"\.php"],
    "ASP.NET": [r"x-aspnet-version", r"asp\.net", r"viewstate"],
    "Next.js": [r"__NEXT_DATA__", r"_next/static", r"_next/image"],
    "Tailwind CSS": [r"tailwind", r"tailwindcss"],
}

def run_fingerprint(target_url):
    """Detect technologies used by the target."""
    safe_print(f"  {Fore.CYAN}[*] TECH: Detecting technologies for {target_url}...{Style.RESET_ALL}")
    resp = http_get(target_url, timeout=15)
    if not resp:
        return []

    html = resp.text
    headers = str(resp.headers).lower()

    detected = []
    for tech, sigs in TECH_SIGNATURES.items():
        for sig in sigs:
            if re.search(sig, html, re.IGNORECASE) or re.search(sig, headers, re.IGNORECASE):
                detected.append(tech)
                break

    return sorted(list(set(detected)))
