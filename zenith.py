import sys
import os
import argparse
import json
import urllib3
from datetime import datetime
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

# Zenith Imports
from core.logger import setup_logger, get_logger, console, success, info, warning, error, ai_msg
from core.config import ConfigManager
from core.state_manager import StateManager
from core.tools_manager import ToolsManager
from core.ai_engine import AIEngine
from core.exporter import ExportManager

from modules.recon import ReconModule
from modules.scanner import ScannerModule
from modules.vuln import VulnModule
from modules.dns import DNSModule

BANNER = """
[bold cyan]
 ███████╗███████╗███╗   ██╗██╗████████╗██╗  ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ╚══███╔╝██╔════╝████╗  ██║██║╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
   ███╔╝ █████╗  ██╔██╗ ██║██║   ██║   ███████║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ███╔╝  ██╔══╝  ██║╚██╗██║██║   ██║   ██╔══██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ███████╗███████╗██║ ╚████║██║   ██║   ██║  ██║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
[/bold cyan]
[bold magenta]           ZenithRecon v1.0 - Advanced Cyber Intelligence System[/bold magenta]
[bold white]                  Autonomous | Collaborative | Professional[/bold white]
"""

def print_banner():
    console.print(Panel(Text.from_markup(BANNER), border_style="cyan"))
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_args():
    parser = argparse.ArgumentParser(description="ZenithRecon - Advanced Reconnaissance Tool")
    parser.add_argument("-t", "--target", help="Target host or URL")
    parser.add_argument("--resume", action="store_true", help="Resume previous scan")
    parser.add_argument("--dry-run", action="store_true", help="Preview phases without execution")
    parser.add_argument("--api-key", help="OpenRouter API Key")
    parser.add_argument("--threads", type=int, help="Maximum concurrent threads")
    parser.add_argument("--timeout", type=int, help="Request timeout in seconds")
    return parser.parse_args()

class ZenithApp:
    def __init__(self):
        self.args = get_args()
        self.config = ConfigManager()

        # Priority: CLI Arg > Config File > Interactive Prompt
        api_key = self.args.api_key or self.config.get("openrouter.api_key")

        if not api_key or api_key.strip() == "":
            print_banner()
            api_key = Prompt.ask("[bold magenta]Enter OpenRouter API Key[/bold magenta]", password=True)
            self.config.set("openrouter.api_key", api_key)
        else:
            self.config.set("openrouter.api_key", api_key)

        if self.args.threads:
            self.config.set("scan.threads", self.args.threads)
        if self.args.timeout:
            self.config.set("scan.timeout", self.args.timeout)

        self.target = self.args.target
        if not self.target:
            print_banner()
            self.target = Prompt.ask("[bold yellow]Enter target host or URL[/bold yellow]")

        # Normalize target
        self.host = self.target.replace("http://", "").replace("https://", "").split("/")[0]
        self.url = f"https://{self.host}" if "://" not in self.target else self.target

        self.output_dir = f"reports/zenith_{self.host.replace('.', '_')}"
        self.logger = setup_logger(self.output_dir)
        self.state = StateManager(self.host, self.output_dir)
        self.tools = ToolsManager(self.config)
        self.ai = AIEngine(self.config)
        self.exporter = ExportManager(self.output_dir)

    def run_human_in_loop(self, strategy):
        ai_msg("Extracting proposed commands for approval...")
        commands = self.ai.propose_commands(strategy)

        if not commands:
            info("No specific commands proposed by AI.")
            return

        info("AI has proposed the following commands for further investigation:")

        for cmd in commands:
            console.print(f"\n[bold cyan]Proposed Command:[/bold cyan] {cmd}")
            choice = Prompt.ask(
                "[bold yellow]Do you want to execute this command?[/bold yellow]",
                choices=["1", "2"],
                default="2"
            )
            # 1 = Yes, 2 = No
            if choice == "1":
                # Safety check
                safety_blacklist = ["rm -rf /", "mkfs", "> /dev/sda", ":(){ :|:& };:"]
                if any(bad in cmd for bad in safety_blacklist):
                    error(f"Command BLOCKED for safety reasons: {cmd}")
                    continue

                info(f"Executing: {cmd}")
                os.system(cmd)
            else:
                info("Skipping command.")

    def run(self):
        print_banner()
        info(f"Targeting: [bold white]{self.host}[/bold white]")

        if self.args.dry_run:
            info("Dry run enabled. Skipping execution.")
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:

            # Phase 1: DNS & Recon
            task1 = progress.add_task("[cyan]Phase 1: Recon & DNS", total=100)
            if not self.state.is_phase_completed("recon"):
                self.state.set_current_phase("recon")
                dns = DNSModule(self.host, self.config, self.tools)
                recon = ReconModule(self.host, self.config)

                progress.update(task1, advance=20, description="[cyan]Resolving DNS...")
                dns_res = dns.run_all()
                progress.update(task1, advance=40, description="[cyan]Fetching Wayback/Emails...")
                recon_res = recon.run_all()

                combined_recon = {**dns_res, **recon_res}
                self.state.update_result("recon", combined_recon)
                progress.update(task1, completed=100, description="[green]Recon Completed.")
            else:
                progress.update(task1, completed=100, description="[yellow]Recon Skipped (Completed).")

            # Phase 2: Scanning
            task2 = progress.add_task("[blue]Phase 2: Port Scanning", total=100)
            if not self.state.is_phase_completed("scan"):
                self.state.set_current_phase("scan")
                scanner = ScannerModule(self.host, self.config)
                ports = scanner.run_common_scan()
                self.state.update_result("scan", {"open_ports": ports})
                progress.update(task2, completed=100, description="[green]Scanning Completed.")
            else:
                progress.update(task2, completed=100, description="[yellow]Scanning Skipped (Completed).")

            # Phase 3: Vulnerabilities
            task3 = progress.add_task("[red]Phase 3: Vulnerabilities", total=100)
            if not self.state.is_phase_completed("vuln"):
                self.state.set_current_phase("vuln")
                vuln = VulnModule(self.url, self.config, self.tools)
                findings = vuln.run_all()
                self.state.update_result("vuln", findings)
                progress.update(task3, completed=100, description="[green]Vuln Assessment Completed.")
            else:
                progress.update(task3, completed=100, description="[yellow]Vuln Skipped (Completed).")

        # Phase 4: AI Collaboration
        info("Synthesizing all data for AI collaboration...")
        try:
            results_data = self.state.state["results"]
            all_results_json = json.dumps(results_data, indent=2)
            strategy = self.ai.collaborate(self.host, all_results_json)

            if strategy:
                console.print(Panel(strategy, title="[bold magenta]AI Collaborative Strategy[/bold magenta]", border_style="magenta"))
                self.state.update_result("ai_strategy", strategy)
                self.run_human_in_loop(strategy)
        except Exception as ai_err:
            error(f"AI Collaboration failed: {ai_err}")

        # Export final data
        try:
            self.exporter.to_json(self.state.state["results"])
            if "vuln" in self.state.state["results"]:
                self.exporter.to_csv(self.state.state["results"]["vuln"])
        except Exception as exp_err:
            error(f"Export failed: {exp_err}")

        success(f"Full ZenithRecon scan for {self.host} completed.")
        info(f"Reports saved in: {self.output_dir}")

if __name__ == "__main__":
    try:
        app = ZenithApp()
        app.run()
    except KeyboardInterrupt:
        warning("\nScan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        error(f"An unexpected error occurred: {e}")
