#!/usr/bin/env python3
"""
DoomScope Setup Script - Automated Installation Helper
This script helps install all required Python packages and checks for external tools.
"""

import subprocess
import sys
import os
import platform
from pathlib import Path

# ANSI Colors for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
    print(f"{text.center(60)}")
    print(f"{'='*60}{Colors.RESET}\n")

def print_success(text):
    print(f"{Colors.GREEN}✓ {text}{Colors.RESET}")

def print_error(text):
    print(f"{Colors.RED}✗ {text}{Colors.RESET}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠ {text}{Colors.RESET}")

def print_info(text):
    print(f"{Colors.BLUE}ℹ {text}{Colors.RESET}")

def run_command(cmd, description="", show_output=False):
    """Run a shell command and return success status."""
    try:
        if show_output:
            result = subprocess.run(cmd, shell=True, check=True)
        else:
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        if description:
            print_success(description)
        return True
    except subprocess.CalledProcessError as e:
        if description:
            print_error(f"{description}: {e}")
        return False
    except Exception as e:
        print_error(f"Error running command: {e}")
        return False

def check_command_exists(cmd, tool_name):
    """Check if a command-line tool exists."""
    try:
        result = subprocess.run(f"which {cmd}" if platform.system() != "Windows" else f"where {cmd}",
                                shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print_success(f"{tool_name} is installed")
            return True
        else:
            print_warning(f"{tool_name} is NOT installed")
            return False
    except:
        print_warning(f"Could not check for {tool_name}")
        return False

def main():
    print_header("DoomScope Setup Assistant")
    
    # ===== STEP 1: Python Version Check =====
    print_info(f"Python Version: {sys.version}")
    if sys.version_info < (3, 8):
        print_error("Python 3.8+ is required. Please upgrade Python.")
        sys.exit(1)
    print_success("Python version is compatible")
    
    # ===== STEP 2: Install Python Requirements =====
    print_header("Step 1: Installing Python Packages")
    
    requirements_file = Path(__file__).parent / "requirements.txt"
    if not requirements_file.exists():
        print_error(f"requirements.txt not found at {requirements_file}")
        sys.exit(1)
    
    print_info(f"Installing from: {requirements_file}")
    if run_command(f"{sys.executable} -m pip install -r {requirements_file}", 
                   "Python packages installed"):
        print_success("All Python packages installed successfully")
    else:
        print_warning("Some Python packages may have failed to install")
    
    # ===== STEP 3: Check External Tools =====
    print_header("Step 2: Checking External Tools")
    
    system = platform.system()
    
    # Check for Go
    print_info("Checking for Go...")
    if not check_command_exists("go", "Go"):
        print_warning("Go is required for nuclei and httpx")
        if system == "Windows":
            print_info("Download from: https://go.dev/dl/")
        else:
            print_info(f"Install Go using your package manager (apt, brew, etc.)")
    
    # Check for nuclei
    print_info("Checking for nuclei...")
    if not check_command_exists("nuclei", "nuclei"):
        print_warning("nuclei is required for vulnerability scanning")
        if run_command(f"{sys.executable} -m pip install nuclei", "", True):
            print_success("nuclei pip package installed")
        else:
            print_info("Install manually: go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
    
    # Check for httpx
    print_info("Checking for httpx...")
    if not check_command_exists("httpx", "httpx"):
        print_warning("httpx v2 is recommended for fingerprinting")
        print_info("Install with: go install github.com/projectdiscovery/httpx/v2/cmd/httpx@latest")
    
    # Check for dirsearch
    print_info("Checking for dirsearch...")
    dirsearch_dir = Path(__file__).parent / "directory_search" / "tools" / "dirsearch"
    if dirsearch_dir.exists():
        print_success("dirsearch directory found")
    else:
        print_warning("dirsearch not found. Will be auto-installed when needed.")
    
    # Check for wapiti
    print_info("Checking for wapiti...")
    if not check_command_exists("wapiti", "wapiti3"):
        print_warning("wapiti3 is optional but recommended")
        if run_command(f"{sys.executable} -m pip install wapiti3", "Installing wapiti3"):
            print_success("wapiti3 installed")
    
    # Check for ChromeDriver
    print_info("Checking for ChromeDriver...")
    if not check_command_exists("chromedriver", "ChromeDriver"):
        print_warning("ChromeDriver is required for browser automation (Selenium)")
        print_info("Download from: https://chromedriver.chromium.org/")
        print_info("Must match your Chrome/Chromium version")
    
    # ===== STEP 4: Summary =====
    print_header("Setup Summary")
    
    print_info("Required Components:")
    print("  ✓ Python 3.8+")
    print("  ✓ Python packages (requirements.txt)")
    print("  ✓ Go 1.17+ (for nuclei & httpx)")
    print("  ✓ nuclei")
    print("  ✓ httpx v2")
    print("  ✓ dirsearch")
    print("  ✓ wapiti3")
    print("  ✓ ChromeDriver (must match Chrome version)")
    
    print_header("Quick Start")
    print(f"{Colors.CYAN}Terminal 1 (Start all services):{Colors.RESET}")
    print(f"  python launcher.py")
    print(f"\n{Colors.CYAN}Terminal 2 (Run pipeline scan):{Colors.RESET}")
    print(f"  python doomscope_pipeline.py")
    print(f"  # Enter target domain when prompted")
    
    print_header("Documentation")
    print(f"See {Colors.BOLD}SERVICES_REQUIREMENTS.md{Colors.RESET} for detailed information about each service.")
    
    print_success("Setup complete! You're ready to use DoomScope.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSetup interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)
