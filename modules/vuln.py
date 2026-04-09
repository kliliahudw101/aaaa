import requests
from core.logger import get_logger, info, warning

logger = get_logger()

class VulnModule:
    def __init__(self, target_url, config, tools_manager=None):
        self.target_url = target_url.rstrip("/")
        self.host = self.target_url.replace("http://", "").replace("https://", "").split("/")[0]
        self.config = config
        self.tools_manager = tools_manager
        self.findings = []

    def check_xss(self):
        info("Performing advanced XSS pattern matching...")

        # 1. Internal Check
        payloads = [
            "<script>alert(1)</script>",
            "\"'><svg/onload=alert(1)>",
            "<img src=x onerror=alert(1)>"
        ]
        for payload in payloads:
            try:
                # Basic reflection check
                test_url = f"{self.target_url}/?search={payload}"
                resp = requests.get(test_url, timeout=10, verify=False)
                if payload in resp.text:
                    self.findings.append({"type": "XSS", "payload": payload, "url": test_url, "severity": "High"})
            except:
                pass

        # 2. External Tool: XSStrike
        if self.tools_manager and self.tools_manager.setup_tool("xsstrike"):
            info(f"Launching XSStrike for deeper XSS analysis on {self.target_url}...")
            tool_cmd = self.tools_manager.get_tool_path("xsstrike")
            if tool_cmd:
                cmd = tool_cmd + ["-u", self.target_url, "--level", "2", "--timeout", "5"]
                result = self.tools_manager.run_command(cmd)
                if result and result.stdout:
                    # Parse or just log output
                    self.findings.append({"type": "XSStrike Output", "data": result.stdout[:500] + "..."})

    def check_traversal(self):
        info("Checking for Directory Traversal...")
        paths = ["/etc/passwd", "/windows/win.ini", "/../../../../etc/passwd"]
        for path in paths:
            try:
                test_url = f"{self.target_url}{path}"
                resp = requests.get(test_url, timeout=10, verify=False)
                if "root:x:" in resp.text or "[extensions]" in resp.text:
                    self.findings.append({"type": "Traversal", "path": path, "url": test_url, "severity": "Critical"})
            except:
                pass

    def check_cors(self):
        info("Checking CORS configuration...")
        try:
            headers = {"Origin": "https://evil.com"}
            resp = requests.get(self.target_url, headers=headers, timeout=10, verify=False)
            acao = resp.headers.get("Access-Control-Allow-Origin")
            if acao == "*" or acao == "https://evil.com":
                self.findings.append({"type": "CORS Misconfig", "acao": acao, "severity": "Medium"})
        except:
            pass

    def run_all(self):
        self.check_xss()
        self.check_traversal()
        self.check_cors()
        return self.findings
