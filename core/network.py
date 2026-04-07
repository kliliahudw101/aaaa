import requests
import time
import socket
import urllib3
import logging
from core.config import G

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def rate_sleep():
    if G.rate_delay > 0:
        time.sleep(G.rate_delay)

def http_request(method, url, timeout=15, allow_redirects=True, headers=None, data=None):
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    }
    if headers:
        default_headers.update(headers)

    rate_sleep()
    try:
        resp = requests.request(
            method=method,
            url=url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            headers=default_headers,
            verify=False,
            proxies=G.proxies,
            data=data,
        )
        return resp
    except Exception as e:
        if G.logger:
            G.logger.error(f"Request error for {url}: {e}")
        return None

def http_get(url, timeout=15, allow_redirects=True, headers=None):
    return http_request("GET", url, timeout, allow_redirects, headers)

def resolve_host(host=None):
    if host is None:
        host = G.target_host
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return "0.0.0.0"
