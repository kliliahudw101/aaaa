import socket
import subprocess
import shutil
from core.logger import get_logger, info, warning, success, error

logger = get_logger()

class DNSModule:
    def __init__(self, target_host, config, tools_manager=None):
        self.target_host = target_host
        self.config = config
        self.tools_manager = tools_manager
        self.results = {"subdomains": [], "takeovers": []}

    def resolve_a(self):
        try:
            ip = socket.gethostbyname(self.target_host)
            self.results["ip"] = ip
            return ip
        except:
            return None

    def run_takeover_check(self):
        if not self.tools_manager:
            return

        info("Running Subdomain Takeover check via 'takeover' tool...")
        if self.tools_manager.setup_tool("takeover"):
            tool_cmd = self.tools_manager.get_tool_path("takeover")
            if tool_cmd:
                # Assuming takeover tool takes a domain via -d
                cmd = tool_cmd + ["-d", self.target_host]
                result = self.tools_manager.run_command(cmd)
                if result and result.stdout:
                    self.results["takeovers"].append(result.stdout)
                    info(f"Takeover tool output recorded.")

    def run_all(self):
        self.resolve_a()
        self.run_takeover_check()
        return self.results
