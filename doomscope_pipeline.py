import requests
import json
import time
from datetime import datetime
import os
import sys
import signal

# ======================= COLORS =======================

class C:
    R = "\033[38;5;160m"
    G = "\033[38;5;82m"
    Y = "\033[38;5;226m"
    B = "\033[38;5;45m"
    P = "\033[38;5;141m"
    W = "\033[38;5;252m"
    E = "\033[0m"

def info(msg):  print(f"{C.B}{msg}{C.E}")
def good(msg):  print(f"{C.G}{msg}{C.E}")
def warn(msg):  print(f"{C.Y}{msg}{C.E}")
def error(msg): print(f"{C.R}{msg}{C.E}")

# ======================= GLOBAL FLAG =======================

STOP_REQUESTED = False

def handle_interrupt(sig, frame):
    global STOP_REQUESTED
    print(f"\n{C.Y}Execution paused.{C.E}")
    choice = input(f"{C.W}Do you want to stop DoomScope? (y/N): {C.E}").strip().lower()
    if choice == "y":
        STOP_REQUESTED = True
        print(f"{C.R}Stopping pipeline safely...{C.E}")
    else:
        print(f"{C.G}Resuming execution...{C.E}")

signal.signal(signal.SIGINT, handle_interrupt)

# ======================= BANNER =======================

def banner():
    print(f"""{C.P}

                 .-=========-.
              .-'      .-.-.   '-.
            .'        .'  | |       '.
           /        .-'    | |           \\
          |       .'       | |              |
          |      |         | |              |
           \\      '.        \\_/            /
            '.        '-.                  .'
              '-.            '-.______.-'

{C.B}      d  o  o  m   s  c  o  p  e{C.E}

{C.W}      automated recon & security framework
      red team  •  attack surface  •  research
{C.E}
""")

# ======================= CONFIG =======================

BASE_URL = "http://127.0.0.1"
HEADERS = {"Content-Type": "application/json"}
OUTPUT_DIR = "final_results"

PIPELINE = [
    ("Subdomain Enumeration", "subdomain_enum", 5000, "/scan"),
    ("Archived Contents", "archived_contents", 5003, "/scan"),
    ("Directory Search", "directory_search", 8000, "/run"),
    ("Tech Fingerprinting", "tech_fingerprinting", 6000, "/techscan"),
    ("Basic Security Scan", "basic_security_scan", 8001, "/run"),
    ("API Enumeration", "api_enum", 8002, "/run"),
    ("Public Parameters", "public_parameters", 6666, "/scan"),
    ("Secret Parameters", "secret_parameters", 5004, "/scan"),
    ("Archived Parameters", "archived_parameters", 9565, "/scan"),
    ("Sensitive Token Archived", "sensitive_token_archivied", 9555, "/scan"),
    ("Sensitive Paths", "sensitive_path_enum", 5001, "/scan"),
    ("Sensitive Logins", "sensitive_login_enum", 5002, "/scan"),
    ("Page Identifier", "page_identifier", 5009, "/scan"),
    ("Public Page Identifier", "public_page_identifier", 5109, "/scan"),
    ("Reflected Params", "reflected_parameter_check", 5122, "/reflect-scan"),
    ("Public Reflected Params", "public_reflected_parameter_check", 6667, "/scan"),
    ("Archived Reflected Params", "archived_reflected_parameter_check", 5222, "/scan"),
    ("JS Analysis", "js_analysis", 8005, "/run"),
    ("Hidden JS Analysis", "hidden_js_analysis", 7002, "/scan"),
    ("Public JS Analysis", "public_js_analysis", 7006, "/scan"),
    ("Archived JS Analysis", "archived_js_analysis", 7072, "/scan"),
    ("Final Security Scanner", "security_scanner", 9998, "/scan"),
]

# ======================= CORE =======================

def run_tool(display_name, tool_name, port, endpoint, domain):
    if STOP_REQUESTED:
        return None

    url = f"{BASE_URL}:{port}{endpoint}"
    payload = {"domain": domain}

    info(f"running {display_name.lower()} ...")
    start = time.time()

    try:
        r = requests.post(
            url,
            json=payload,
            headers=HEADERS
        )

        if r.status_code != 200:
            raise Exception(f"http {r.status_code}")

        data = r.json()

    except Exception as e:
        error(f"{display_name.lower()} failed: {e}")
        return {
            "tool": tool_name,
            "status": "failed",
            "error": str(e)
        }

    elapsed = round(time.time() - start, 2)
    good(f"{display_name.lower()} completed in {elapsed}s")

    return {
        "tool": tool_name,
        "status": "success",
        "elapsed_seconds": elapsed,
        "response": data
    }

# ======================= MAIN =======================

def main():
    banner()

    domain = input(f"{C.W}target domain > {C.E}").strip()

    if not domain:
        error("no domain provided")
        return

    info(f"target locked: {domain}")
    print()

    results = []

    for step in PIPELINE:
        if STOP_REQUESTED:
            break

        result = run_tool(*step, domain)
        if result:
            results.append(result)

        time.sleep(0.4)

    final_report = {
        "framework": "doomscope",
        "version": "1.1.0",
        "target": domain,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "completed": not STOP_REQUESTED,
        "results": results
    }

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_file = os.path.join(
        OUTPUT_DIR,
        f"{domain.replace('.', '_')}_doomscope_report.json"
    )

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(final_report, f, indent=2, ensure_ascii=False)

    if STOP_REQUESTED:
        warn("execution stopped by user")
    else:
        good("pipeline completed successfully")

    good(f"report saved to {out_file}")

# ======================= RUN =======================

if __name__ == "__main__":
    main()
