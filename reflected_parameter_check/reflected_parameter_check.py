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
from colorama import Fore, Style, init

init(autoreset=True)

app = Flask(__name__)


# ============================================================
# Helper Functions
# ============================================================

def random_marker():
    return "MK_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))


def build_url(base_url, param, value):
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query)
    qs[param] = value
    new_qs = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_qs))


def create_driver():
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    return webdriver.Chrome(options=chrome_options)


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

        html_text = soup.get_text()

        if marker in html or marker in html_text:
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

@app.route("/reflect-scan", methods=["POST"])
def reflect_scan():
    data = request.get_json()
    domain = data.get("domain")

    if not domain:
        return jsonify({"error": "Missing domain"}), 400

    file_path = f"../secret_parameters/{domain.replace('.', '_')}_results.txt"

    if not os.path.exists(file_path):
        return jsonify({"error": f"File not found: {file_path}"}), 404

    results_json = json.load(open(file_path, "r"))
    all_tasks = []

    print(Fore.MAGENTA + f"\n[+] Starting reflection scan for {domain}")

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []

        for entry in results_json.get("results", []):
            url = entry["url"]
            params = entry["parameters"]

            for param in params:
                futures.append(executor.submit(test_reflection, url, param))

        for future in as_completed(futures):
            all_tasks.append(future.result())

    # ============================================================
    # Save results to current directory
    # ============================================================
    output_file = f"{domain.replace('.', '_')}_selenium_reflection.json"
    with open(output_file, "w") as f:
        json.dump(all_tasks, f, indent=4)

    print(Fore.GREEN + f"\n[✓] Results saved to: {output_file}")

    return jsonify({
        "status": "done",
        "domain": domain,
        "total_tests": len(all_tasks),
        "results": all_tasks,
        "saved_file": output_file
    })


# ============================================================
# Run Flask
# ============================================================

if __name__ == "__main__":
    app.run(port=5122, debug=True)
