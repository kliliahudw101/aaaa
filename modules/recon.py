import re
import requests
from core.config import G, safe_print, t, Fore, Style
from core.network import http_get

SOCIAL_MEDIA_PATTERNS = {
    "Facebook": [r'facebook\.com', r'fb\.com', r'fb\.me'],
    "Twitter/X": [r'twitter\.com', r'x\.com', r't\.co'],
    "LinkedIn": [r'linkedin\.com'],
    "Instagram": [r'instagram\.com'],
    "YouTube": [r'youtube\.com', r'youtu\.be'],
    "GitHub": [r'github\.com'],
    "GitLab": [r'gitlab\.com'],
    "TikTok": [r'tiktok\.com'],
    "Reddit": [r'reddit\.com'],
    "Discord": [r'discord\.com', r'discord\.gg'],
    "Telegram": [r't\.me', r'telegram\.org'],
    "WhatsApp": [r'wa\.me', r'web\.whatsapp\.com'],
    "Pinterest": [r'pinterest\.com'],
    "Snapchat": [r'snapchat\.com'],
    "Twitch": [r'twitch\.tv'],
    "Medium": [r'medium\.com'],
}

def run_reconnaissance(target_url):
    """Run comprehensive reconnaissance on the target URL."""
    safe_print(f"  {Fore.CYAN}[*] RECON: Starting reconnaissance for {target_url}...{Style.RESET_ALL}")

    resp = http_get(target_url, timeout=15)
    if not resp:
        return {"error": "Could not connect to target URL."}

    html = resp.text
    headers = resp.headers

    # 1. Header analysis
    headers_info = {k: v for k, v in headers.items()}

    # 2. Email harvesting
    email_pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    emails = sorted(set(re.findall(email_pattern, html)))

    # 3. Social media links
    social_links = {}
    for platform, patterns in SOCIAL_MEDIA_PATTERNS.items():
        found = []
        for p in patterns:
            matches = re.findall(rf'(https?://[^\s"\'<>]*{p}[^\s"\'<>]*)', html, re.IGNORECASE)
            found.extend(matches)
        if found:
            social_links[platform] = sorted(set(found))

    # 4. Robots.txt check
    robots_url = f"{target_url.rstrip('/')}/robots.txt"
    robots_resp = http_get(robots_url, timeout=10)
    robots_content = robots_resp.text if robots_resp and robots_resp.status_code == 200 else "Not found"

    # 5. Extract links
    external_links = sorted(set(re.findall(r'href=["\'](https?://[^\s"\'<>]+)["\']', html)))

    return {
        "status_code": resp.status_code,
        "headers": headers_info,
        "emails": emails,
        "social": social_links,
        "robots_txt": robots_content,
        "external_links": external_links
    }
