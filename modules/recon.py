import requests
import re
from core.logger import get_logger, info, error

logger = get_logger()

class ReconModule:
    def __init__(self, target_host, config):
        self.target_host = target_host
        self.config = config
        self.results = {}

    def fetch_wayback_urls(self, limit=100):
        info(f"Fetching URLs from Wayback Machine for {self.target_host}...")
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url={self.target_host}/*&output=json&limit={limit}&fl=original"
            resp = requests.get(url, timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                if len(data) > 1:
                    urls = [row[0] for row in data[1:]]
                    unique_urls = list(set(urls))
                    self.results["wayback_urls"] = unique_urls
                    return unique_urls
            return []
        except Exception as e:
            error(f"Wayback Machine fetch failed: {e}")
            return []

    def harvest_emails(self, text_content):
        info("Harvesting emails from discovered content...")
        email_pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, text_content)
        unique_emails = list(set(emails))
        self.results["emails"] = unique_emails
        return unique_emails

    def run_all(self):
        self.fetch_wayback_urls()
        # Initial page fetch for emails
        try:
            resp = requests.get(f"https://{self.target_host}", timeout=10, verify=False)
            if resp.status_code == 200:
                self.harvest_emails(resp.text)
        except:
            pass
        return self.results
