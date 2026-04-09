import socket
from concurrent.futures import ThreadPoolExecutor
from core.logger import get_logger, info, success

logger = get_logger()

class ScannerModule:
    def __init__(self, target_host, config):
        self.target_host = target_host
        self.config = config
        self.threads = config.get("scan.threads", 20)
        self.timeout = config.get("scan.timeout", 5)
        self.open_ports = []

    def scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                if s.connect_ex((self.target_host, port)) == 0:
                    self.open_ports.append(port)
                    return True
        except:
            pass
        return False

    def run_common_scan(self):
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
        info(f"Scanning {len(common_ports)} common ports on {self.target_host}...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.scan_port, common_ports)

        self.open_ports.sort()
        if self.open_ports:
            success(f"Open ports found: {self.open_ports}")
        return self.open_ports
