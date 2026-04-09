import requests
import json
import time
import yaml
import os
from core.logger import get_logger, ai_msg, error, warning

logger = get_logger()

class AIEngine:
    def __init__(self, config):
        self.config = config
        self.api_key = config.get("openrouter.api_key")
        self.base_url = config.get("openrouter.base_url", "https://openrouter.ai/api/v1")
        self.models = config.get("openrouter.models")
        self.prompts = self.load_prompts()

    def load_prompts(self):
        prompt_path = "config/prompts.yaml"
        if os.path.exists(prompt_path):
            with open(prompt_path, 'r') as f:
                return yaml.safe_load(f)
        return {}

    def call_model(self, model_role, prompt, system_prompt=None):
        """Calls a specific model based on its role (triage, analysis, synthesis)."""
        model_name = self.models.get(model_role)
        if not self.api_key:
            warning("OpenRouter API key missing. AI analysis will be skipped.")
            return None

        if not model_name:
            error(f"No model configured for role: {model_role}")
            return None

        if not system_prompt:
            system_prompt = "You are a senior cybersecurity expert in an intelligence-driven reconnaissance framework."

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/zenith-recon",
            "X-Title": "ZenithRecon"
        }

        data = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3
        }

        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                data=json.dumps(data),
                timeout=60
            )
            response.raise_for_status()
            result = response.json()
            content = result['choices'][0]['message']['content']
            ai_msg(f"{model_role.capitalize()} model ({model_name}) responded.")
            return content
        except Exception as e:
            error(f"AI call failed for {model_name}: {e}")
            return None

    def collaborate(self, target, phase_data):
        """Orchestrates collaboration between the three models."""
        ai_msg("Initiating model collaboration...")

        # 1. Triage (Stepfun)
        triage_prompt = self.prompts.get("triage", "").format(target=target, data=phase_data)
        triage_results = self.call_model("triage", triage_prompt)
        if not triage_results:
            return "Collaboration failed at Triage phase."

        # 2. Deep Analysis (Nemotron)
        analysis_prompt = self.prompts.get("analysis", "").format(target=target, data=triage_results)
        analysis_results = self.call_model("analysis", analysis_prompt)
        if not analysis_results:
            return f"Collaboration partial. Triage results:\n{triage_results}"

        # 3. Final Synthesis & Strategy (GLM)
        combined_reports = f"TRIAGE:\n{triage_results}\n\nANALYSIS:\n{analysis_results}"
        synthesis_prompt = self.prompts.get("synthesis", "").format(target=target, data=combined_reports)
        final_strategy = self.call_model("synthesis", synthesis_prompt)

        return final_strategy

    def propose_commands(self, strategy_text):
        """Extracts proposed commands from the AI strategy."""
        prompt = self.prompts.get("command_extraction", "").format(data=strategy_text)
        commands_json = self.call_model("triage", prompt, system_prompt="You are a command extractor. Output ONLY valid JSON.")

        try:
            # Clean JSON if AI added markdown code blocks
            if "```json" in commands_json:
                commands_json = commands_json.split("```json")[1].split("```")[0]
            elif "```" in commands_json:
                commands_json = commands_json.split("```")[1].split("```")[0]

            commands = json.loads(commands_json.strip())
            return commands
        except Exception as e:
            logger.debug(f"Failed to parse commands from AI: {e}")
            return []
