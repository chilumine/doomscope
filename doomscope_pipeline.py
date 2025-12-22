import requests
import json
import os
import time
from datetime import datetime

# ======================= CLI STYLE =======================

def banner():
    print("""
██████╗  ██████╗  ██████╗ ███╗   ███╗███████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔═══██╗██╔═══██╗████╗ ████║██╔════╝██╔════╝██╔═══██╗██╔════╝
██║  ██║██║   ██║██║   ██║██╔████╔██║███████╗██║     ██║   ██║█████╗  
██║  ██║██║   ██║██║   ██║██║╚██╔╝██║╚════██║██║     ██║   ██║██╔══╝  
██████╔╝╚██████╔╝╚██████╔╝██║ ╚═╝ ██║███████║╚██████╗╚██████╔╝███████╗
╚═════╝  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝
           DoomScope | Automated Web Security Testing Framework
    """)


def info(msg):    print(f"[*] {msg}")
def good(msg):    print(f"[✓] {msg}")
def warn(msg):    print(f"[!] {msg}")
def error(msg):   print(f"[✗] {msg}")

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
    url = f"{BASE_URL}:{port}{endpoint}"
    payload = {"domain": domain}

    info(f"{display_name} → RUNNING")
    start = time.time()

    try:
        r = requests.post(url, json=payload, headers=HEADERS)
        if r.status_code != 200:
            raise Exception(f"HTTP {r.status_code}")
    except Exception as e:
        error(f"{display_name} FAILED ({e})")
        raise SystemExit

    elapsed = round(time.time() - start, 2)
    good(f"{display_name} DONE in {elapsed}s\n")
    time.sleep(1)


def collect_json():
    info("Collecting JSON results...")
    merged = {}

    for root, _, files in os.walk("."):
        for f in files:
            if not f.endswith(".json"):
                continue

            path = os.path.join(root, f)
            try:
                with open(path, "r", encoding="utf-8") as file:
                    data = json.load(file)
            except Exception:
                continue

            merged.setdefault(root, []).append({
                "file": path,
                "data": data
            })

    return merged

# ======================= MAIN =======================

def main():
    banner()

    domain = input("🌐 Enter target domain (example.com): ").strip()

    if not domain:
        error("No domain provided")
        return

    info(f"Target set → {domain}")
    info("Initial Fingerprinting → SKIPPED\n")

    for step in PIPELINE:
        run_tool(*step, domain)

    results = collect_json()

    final = {
        "domain": domain,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "pipeline": [s[0] for s in PIPELINE],
        "results": results
    }

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_file = os.path.join(
        OUTPUT_DIR,
        f"{domain.replace('.', '_')}_doomscope_report.json"
    )

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(final, f, indent=2, ensure_ascii=False)

    good("Pipeline Completed Successfully")
    good(f"Unified JSON saved → {out_file}")

# ======================= RUN =======================

if __name__ == "__main__":
    main()
