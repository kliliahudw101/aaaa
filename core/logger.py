import logging
import os
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# Custom theme for ZenithRecon
ZENITH_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "red",
    "critical": "bold red",
    "success": "green",
    "ai": "magenta",
    "tool": "blue"
})

console = Console(theme=ZENITH_THEME)

def setup_logger(output_dir=None):
    """Sets up the ZenithRecon logger with Rich and file support."""
    logger = logging.getLogger("zenith")
    logger.setLevel(logging.DEBUG)

    # Remove existing handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    # Rich Console Handler
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True
    )
    rich_handler.setLevel(logging.INFO)
    logger.addHandler(rich_handler)

    # File Handler (if output_dir is provided)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        log_file = os.path.join(output_dir, "zenith_scan.log")
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger

def get_logger():
    return logging.getLogger("zenith")

# Helper functions for themed printing
def success(message):
    console.print(f"[success][+] {message}[/success]")

def warning(message):
    console.print(f"[warning][!] {message}[/warning]")

def error(message):
    console.print(f"[error][-] {message}[/error]")

def info(message):
    console.print(f"[info][*] {message}[/info]")

def ai_msg(message):
    console.print(f"[ai][AI] {message}[/ai]")
