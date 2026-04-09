import os
import subprocess
import shutil
from core.logger import get_logger, success, info, warning, error

logger = get_logger()

class ToolsManager:
    def __init__(self, config):
        self.config = config
        self.tools_base_dir = config.get("tools.base_dir", "tools")
        os.makedirs(self.tools_base_dir, exist_ok=True)

    def is_installed(self, tool_command):
        """Checks if a command-line tool is installed in the system PATH."""
        return shutil.which(tool_command) is not None

    def check_local_install(self, tool_name):
        """Checks if a tool is installed in the local tools directory."""
        tool_path = self.config.get(f"tools.{tool_name}.path")
        if tool_path and os.path.exists(tool_path):
            return True
        return False

    def setup_tool(self, tool_name):
        """Ensures a tool is available (system-wide or local). If not, tries to clone it."""
        repo_url = self.config.get(f"tools.{tool_name}.repo")
        tool_path = self.config.get(f"tools.{tool_name}.path")

        if self.is_installed(tool_name):
            success(f"Tool '{tool_name}' is already available in system PATH.")
            return True

        if self.check_local_install(tool_name):
            success(f"Tool '{tool_name}' is available at {tool_path}")
            return True

        if repo_url:
            info(f"Tool '{tool_name}' not found. Attempting to install from {repo_url}...")
            try:
                subprocess.run(["git", "clone", repo_url, tool_path], check=True)
                success(f"Successfully cloned {tool_name}")

                # Try to install requirements if it's a python tool
                req_file = os.path.join(tool_path, "requirements.txt")
                if os.path.exists(req_file):
                    info(f"Installing requirements for {tool_name}...")
                    subprocess.run(["pip", "install", "-r", req_file], check=False)

                return True
            except Exception as e:
                error(f"Failed to install {tool_name}: {e}")
                return False

        return False

    def run_command(self, cmd_list, capture_output=True):
        """Runs a tool command and handles potential errors."""
        try:
            result = subprocess.run(
                cmd_list,
                capture_output=capture_output,
                text=True,
                check=False
            )
            return result
        except Exception as e:
            error(f"Error executing command {' '.join(cmd_list)}: {e}")
            return None

    def get_tool_path(self, tool_name):
        """Returns the best path/command to run the tool."""
        if self.is_installed(tool_name):
            return [tool_name]

        tool_path = self.config.get(f"tools.{tool_name}.path")
        if tool_path:
            # Check for common entry points
            for entry in ["main.py", f"{tool_name}.py", "run.sh"]:
                full_entry = os.path.join(tool_path, entry)
                if os.path.exists(full_entry):
                    if entry.endswith(".py"):
                        return ["python3", full_entry]
                    return [full_entry]

        return None
