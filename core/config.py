import os
import sys
import re
import json
import socket
import ssl
import subprocess
import shutil
import logging
import datetime
import time
import urllib.parse
from threading import Lock
from colorama import init, Fore, Back, Style

init(autoreset=True)

class GlobalState:
    """Thread-safe global state for the scanner."""
    def __init__(self):
        self.lang = "en"
        self.target_url = ""
        self.target_host = ""
        self.target_scheme = "https"
        self.base_path = ""
        self.scan_level = "standard"
        self.models_config = []
        self.openrouter_api_key = ""
        self.output_dir = ""
        self.output_base = "."
        self.scan_start_time = None
        self.results = {}
        self.nmap_available = False
        self.openssl_available = False
        self.selected_phases = set()
        self.print_lock = Lock()
        self.results_lock = Lock()
        self.proxy = None
        self.proxies = {}
        self.rate_delay = 0.1
        self.logger = None

    def get_results(self):
        with self.results_lock:
            return dict(self.results)

    def set_result(self, phase_num, content):
        with self.results_lock:
            self.results[phase_num] = self.results.get(phase_num, "") + content

G = GlobalState()

STRINGS = {
    "en": {
        "banner": "{cyan}Deep Recon Framework v5.0 (Modular Edition){reset}",
        # ... Add other strings as needed
    },
    "ar": {
        "banner": "{cyan}فريمورك الفحص العميق v5.0 (النسخة المعيارية){reset}",
        # ... Add other strings as needed
    }
}

def t(key, **kwargs):
    lang = getattr(G, 'lang', 'en')
    s = STRINGS.get(lang, STRINGS["en"]).get(key, STRINGS["en"].get(key, key))
    try:
        return s.format(cyan=Fore.CYAN, green=Fore.GREEN, yellow=Fore.YELLOW,
                        red=Fore.RED, blue=Fore.BLUE, magenta=Fore.MAGENTA,
                        dim=Style.DIM, bold=Style.BRIGHT, reset=Style.RESET_ALL,
                        **kwargs)
    except (KeyError, IndexError):
        return s

def safe_print(msg, **kwargs):
    with G.print_lock:
        print(msg, **kwargs)

def setup_logging(output_dir):
    log_file = os.path.join(output_dir, "scan.log")
    logger = logging.getLogger("deep_recon")
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(fh)
    G.logger = logger
    return logger
