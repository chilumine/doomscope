from flask import Flask, request, jsonify
import os
import json
import random
import string
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, init

init(autoreset=True)

app = Flask(__name__)

# ============================================================
# Helpers
# ============================================================

def random_marker():
    return "MK_" + "".join(
        random.choices(string.ascii_lowercase + string.digits, k=12)
    )

def build_url(base_url, param, value):
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query)
    qs[param] = value
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

def create_driver():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--log-level=3")
    return webdriver.Chrome(options=options)

# ============================================================
# Load parameters from ../api_enum/public_parameters
# ============================================================

def load_parameters_file(domain):
    base_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "api_enum", "public_parameters")
    )

    path = os.path.join(base_dir, f"{domain}.txt")

    if not os.path.isfile(path):
        return None, f"File not found: {path}"

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f), None

# ============================================================
# Reflection Test
# ============================================================

def test_reflection(url, param):
    marker = random_marker()
    test_url = build_url(url, param, marker)

    print(Fore.CYAN + f"[•] Testing {param} → {test_url}")

    driver = None
    reflected = False

    try:
        driver = create_driver()
        driver.get(test_url)

        html = driver.page_source
        soup = BeautifulSoup(html, "html.parser")

        if marker in html or marker in soup.get_text(" "):
            reflected = True
            print(Fore.GREEN + f"[✔] Reflected → {param}")
        else:
            print(Fore.RED + f"[×] Not reflected → {param}")

    except Exception as e:
        print(Fore.YELLOW + f"[!] Error testing {param}: {e}")

    finally:
        if driver:
            driver.quit()

    return {
        "url": url,
        "tested_url": test_url,
        "parameter": param,
        "marker": marker,
        "reflected": reflected
    }

# ============================================================
# API Endpoint
# ============================================================

@app.route("/scan", methods=["POST"])
def reflect_scan():
    data = request.get_json()
    domain = data.get("domain")

    if not domain:
        return jsonify({"error": "Missing domain"}), 400

    params_json, error = load_parameters_file(domain)
    if error:
        return jsonify({"error": error}), 404

    print(Fore.MAGENTA + f"\n[+] Starting reflection scan for {domain}")

    results = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []

        for entry in params_json.get("endpoints_with_parameters", []):
            url = entry.get("url")
            for param in entry.get("parameters", []):
                futures.append(
                    executor.submit(test_reflection, url, param)
                )

        for f in as_completed(futures):
            results.append(f.result())

    # ============================================================
    # Save Results — ARRAY ONLY (Final Required Format)
    # ============================================================
    safe_domain = domain.replace(".", "_")
    output_file = os.path.join(
        os.getcwd(),
        f"public_{safe_domain}_selenium_reflection.txt"
    )

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(Fore.GREEN + f"\n[✓] Results saved to: {output_file}")

    return jsonify({
        "status": "done",
        "domain": domain,
        "total_tests": len(results),
        "saved_file": output_file,
        "results": results
    })

# ============================================================
# Run
# ============================================================

if __name__ == "__main__":
    app.run(port=6667, debug=True)
