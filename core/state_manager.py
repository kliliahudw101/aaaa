import json
import os
from core.logger import get_logger

logger = get_logger()

class StateManager:
    """Manages the scan state to allow pausing and resuming."""
    def __init__(self, target_host, output_dir):
        self.target_host = target_host
        self.output_dir = output_dir
        self.state_file = os.path.join(output_dir, "scan_state.json")
        self.state = {
            "target": target_host,
            "completed_phases": [],
            "results": {},
            "start_time": None,
            "current_phase": None
        }
        self.load()

    def load(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    saved_state = json.load(f)
                    self.state.update(saved_state)
                logger.info(f"Loaded existing scan state for {self.target_host}")
            except Exception as e:
                logger.error(f"Failed to load scan state: {e}")

    def save(self):
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save scan state: {e}")

    def update_result(self, phase, result_data):
        self.state["results"][phase] = result_data
        if phase not in self.state["completed_phases"]:
            self.state["completed_phases"].append(phase)
        self.save()

    def is_phase_completed(self, phase):
        return phase in self.state["completed_phases"]

    def set_start_time(self, timestamp):
        self.state["start_time"] = timestamp
        self.save()

    def set_current_phase(self, phase):
        self.state["current_phase"] = phase
        self.save()
