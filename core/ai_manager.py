import requests
import json
import logging
from colorama import Fore, Style
from core.config import G, t, safe_print

class AIManager:
    """Manager for OpenRouter and Collaborative AI routing."""

    MODELS = {
        "primary": "stepfun/step-3.5-flash:free",      # Identification & Strategy
        "auditor": "z-ai/glm-4.5-air:free",           # Validation & False Positive reduction
        "exploit": "nvidia/nemotron-3-super-120b-a12b:free" # PoC & Exploit development
    }

    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {api_key}" if api_key else "",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://deep-recon.security.local",
            "X-Title": "Deep Recon Scanner v5.0",
        }

    def call_model(self, model, prompt, system_prompt="You are a senior cybersecurity expert.", timeout=60, temperature=0.3):
        """Generic OpenRouter call."""
        try:
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=self.headers,
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
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

    def collaborative_scan_analysis(self, raw_data):
        """
        Phase 1: Identification (Stepfun)
        Phase 2: Audit & Validation (GLM)
        Phase 3: Final Consolidation (Stepfun)
        """
        lang_instr = "Respond in Arabic." if G.lang == "ar" else "Respond in English."

        # 1. Identification
        safe_print(f"  {Fore.CYAN}[*] AI: Identifying vulnerabilities (Stepfun)...{Style.RESET_ALL}")
        id_prompt = f"Analyze the following security scan data and identify potential vulnerabilities and entry points:\n\n{raw_data}\n\n{lang_instr}"
        id_report = self.call_model(self.MODELS["primary"], id_prompt, "You are a specialized security identification expert.")

        # 2. Audit
        safe_print(f"  {Fore.CYAN}[*] AI: Auditing findings for accuracy (GLM)...{Style.RESET_ALL}")
        audit_prompt = f"Review the following security findings. Validate if they are likely correct or potential false positives. Point out any missed details:\n\n{id_report}\n\nOriginal Data for context:\n{raw_data[:5000]}\n\n{lang_instr}"
        audit_report = self.call_model(self.MODELS["auditor"], audit_prompt, "You are a rigorous security auditor. Your goal is to reduce false positives.")

        # 3. Final Consolidation
        safe_print(f"  {Fore.CYAN}[*] AI: Finalizing strategic report...{Style.RESET_ALL}")
        final_prompt = f"Based on the initial findings and the audit review, produce the final consolidated security assessment. Resolve any conflicts between the initial report and the audit:\n\nInitial findings: {id_report}\n\nAudit review: {audit_report}\n\n{lang_instr}"
        final_report = self.call_model(self.MODELS["primary"], final_prompt)

        return final_report

    def collaborative_exploit_gen(self, vulnerabilities):
        """
        Phase 1: Exploit Strategy (Nvidia)
        Phase 2: Safety & Accuracy Check (GLM)
        """
        lang_instr = "Respond in Arabic." if G.lang == "ar" else "Respond in English."

        safe_print(f"  {Fore.CYAN}[*] AI: Developing exploit PoCs (Nvidia)...{Style.RESET_ALL}")
        strat_prompt = f"For the following confirmed vulnerabilities, provide detailed PoC scripts (Python/Curl) and exploitation steps:\n\n{vulnerabilities}\n\n{lang_instr}"
        strat_out = self.call_model(self.MODELS["exploit"], strat_prompt, "You are an expert exploit developer.")

        safe_print(f"  {Fore.CYAN}[*] AI: Reviewing exploit code for accuracy (GLM)...{Style.RESET_ALL}")
        review_prompt = f"Review the following exploit PoCs and instructions. Ensure they are technically accurate and match the vulnerabilities described. Provide improvements if needed:\n\n{strat_out}\n\n{lang_instr}"
        final_exploits = self.call_model(self.MODELS["auditor"], review_prompt, "You are a senior security researcher reviewing exploit code.")

        return final_exploits
