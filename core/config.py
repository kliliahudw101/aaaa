import yaml
import os
from core.logger import get_logger

logger = get_logger()

DEFAULT_CONFIG = {
    "openrouter": {
        "api_key": "",
        "base_url": "https://openrouter.ai/api/v1",
        "models": {
            "triage": "stepfun/step-3.5-flash:free",
            "analysis": "nvidia/nemotron-3-super-120b-a12b:free",
            "synthesis": "z-ai/glm-4.5-air:free"
        }
    },
    "scan": {
        "threads": 20,
        "timeout": 15,
        "rate_limit": 0.1,
        "user_agent": "ZenithRecon/1.0 (Professional Security Reconnaissance)"
    },
    "tools": {
        "base_dir": "tools",
        "xsstrike": {
            "repo": "https://github.com/s0md3v/XSStrike.git",
            "path": "tools/XSStrike"
        },
        "takeover": {
            "repo": "https://github.com/edoardottt/takeover.git",
            "path": "tools/takeover"
        }
    }
}

class ConfigManager:
    def __init__(self, config_path="config/settings.yaml"):
        self.config_path = config_path
        self.config = DEFAULT_CONFIG.copy()
        self.load()

    def load(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    if user_config:
                        self._deep_update(self.config, user_config)
                logger.debug(f"Configuration loaded from {self.config_path}")
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
        else:
            self.save() # Create default config file if it doesn't exist

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
            logger.info(f"Default configuration saved to {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")

    def _deep_update(self, base, update):
        for k, v in update.items():
            if isinstance(v, dict) and k in base:
                self._deep_update(base[k], v)
            else:
                base[k] = v

    def get(self, key_path, default=None):
        keys = key_path.split('.')
        val = self.config
        try:
            for k in keys:
                val = val[k]
            return val
        except (KeyError, TypeError):
            return default

    def set(self, key_path, value):
        keys = key_path.split('.')
        val = self.config
        for k in keys[:-1]:
            if k not in val:
                val[k] = {}
            val = val[k]
        val[keys[-1]] = value
        self.save()
