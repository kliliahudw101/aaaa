import requests
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from colorama import Fore, Style
from core.config import G, t, safe_print

class AIManager:
    """Manager for OpenRouter and AI routing."""

    MODELS = {
        "primary": "stepfun/step-3.5-flash:free",
        "exploit": "nvidia/nemotron-3-super-120b-a12b:free",
        "analysis": "z-ai/glm-4.5-air:free"
    }

    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {api_key}" if api_key else "",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://deep-recon.security.local",
            "X-Title": "Deep Recon Scanner v5.0",
        }

    def call_model(self, model, prompt, timeout=60, temperature=0.3):
        """Generic OpenRouter call."""
        try:
            # Fixed insecure API call (removed verify=False for OpenRouter)
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=self.headers,
                json={
                    "model": model,
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a senior cybersecurity penetration testing expert. "
                                      "Provide detailed, actionable security analysis. "
                                      "Always include specific CVE numbers when applicable. "
                                      "Structure your response with clear headings and bullet points."
                        },
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": 4096,
                    "temperature": temperature,
                },
                timeout=timeout + 10,
                proxies=G.proxies,
            )
            data = response.json()
            if "choices" in data and data["choices"]:
                return data["choices"][0]["message"]["content"]
            elif "error" in data:
                return f"ERROR: {data['error']}"
            return f"ERROR: Unexpected response: {json.dumps(data)[:500]}"
        except Exception as e:
            if G.logger:
                G.logger.error(f"AI call error: {e}")
            return f"ERROR: {str(e)}"

    def strategic_analysis(self, scan_results):
        prompt = f"Perform a comprehensive strategic analysis for the target based on these results:\n\n{scan_results}"
        return self.call_model(self.MODELS["primary"], prompt)

    def generate_poc(self, finding_details):
        prompt = f"As an exploit developer, provide a detailed PoC script (Python/Curl) and exploitation guide for this finding:\n\n{finding_details}"
        return self.call_model(self.MODELS["exploit"], prompt)

    def technical_summary(self, scan_results):
        prompt = f"Summarize these scan findings with a focus on risk and remediation:\n\n{scan_results}"
        return self.call_model(self.MODELS["analysis"], prompt)

    def route_task(self, task_type, content):
        """Route task to the most suitable model."""
        if task_type == "exploit":
            return self.generate_poc(content)
        elif task_type == "analysis":
            return self.technical_summary(content)
        else:
            return self.strategic_analysis(content)
