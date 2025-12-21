from flask import Flask, request, jsonify
import os
import re
import json
import sys
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)

app = Flask(__name__)

DETECTORS_DIR = "detectors"
PAGE_IDENTIFIER_RESULTS_DIR = "page_identifier"

# ===============================================
# Disable Selenium / Chrome noise
# ===============================================
def silent_chrome_options():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--log-level=3")
    options.add_argument("--silent")
    options.add_argument("--disable-logging")
    options.add_argument("--disable-software-rasterizer")
    options.add_experimental_option("excludeSwitches", ["enable-logging"])
    return options

# ===============================================
# Load detectors
# ===============================================
def load_detectors():
    detectors = []
    for file in os.listdir(DETECTORS_DIR):
        if file.endswith(".json"):
            with open(os.path.join(DETECTORS_DIR, file), "r", encoding="utf-8") as f:
                detectors.append(json.load(f))
    return detectors

# ===============================================
# HTML scoring
# ===============================================
def check_html_signals(soup, detector):
    html = detector["html"]
    score = 0
    for sel in html.get("required", []):
        if soup.select(sel):
            score += detector["scoring"].get("html_required", 0)
    for sel in html.get("optional", []):
        if soup.select(sel):
            score += detector["scoring"].get("html_optional", 0)
    for sel in html.get("forbidden", []):
        if soup.select(sel):
            score += detector["scoring"].get("forbidden_penalty", 0)
    return score

# ===============================================
# Text scoring
# ===============================================
def check_text_signals(text, detector):
    t = detector["text"]
    score = 0
    for word in t.get("required", []):
        if word.lower() in text:
            score += detector["scoring"].get("text_required", 0)
    for word in t.get("optional", []):
        if word.lower() in text:
            score += detector["scoring"].get("text_optional", 0)
    for word in t.get("forbidden", []):
        if word.lower() in text:
            score += detector["scoring"].get("forbidden_penalty", 0)
    return score

# ===============================================
# Analyze page
# ===============================================
def analyze_page(html, detector):
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ").lower()
    score = check_html_signals(soup, detector) + check_text_signals(text, detector)
    if score >= detector.get("logic", {}).get("min_total_score", 1):
        return detector["name"]
    return None

# ===============================================
# Identify page for a single URL
# ===============================================
def identify_page(url):
    options = silent_chrome_options()
    devnull = open(os.devnull, "w")
    sys.stderr = devnull

    try:
        driver = webdriver.Chrome(options=options)
        driver.get(url)
        html = driver.page_source
        driver.quit()
    except Exception:
        html = ""
    finally:
        sys.stderr = sys.__stderr__

    detectors = load_detectors()
    matches = []
    for d in detectors:
        res = analyze_page(html, d)
        if res:
            matches.append(res)
    return matches

# ===============================================
# Parse 200/500 URLs from dirsearch result file
# ===============================================
def extract_urls_from_file(filepath):
    urls = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                m = re.match(r"(\d{3})\s+[^\s]+\s+(https?://[^\s]+)", line)
                if m:
                    status = int(m.group(1))
                    if status in (200, 500):
                        urls.append(m.group(2))
    except Exception:
        pass
    return urls

# ===============================================
# Ignore static files
# ===============================================
def is_static(url):
    static_ext = (
        ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".css", ".js", ".ico", ".woff", ".ttf",
        ".txt", ".log", ".zip", ".pdf", ".yaml", ".yml"
    )
    if any(url.lower().endswith(ext) for ext in static_ext):
        return True
    if "robots.txt" in url.lower() or "sitemap" in url.lower():
        return True
    return False

# ===============================================
# Process domain folder and identify pages
# ===============================================
def process_domain(domain):
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    # Use dirsearch/results located one level above this script
    BASE_RESULTS_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "directory_search", "results"))
    folder_name = domain.replace(".", "_")
    folder_path = os.path.join(BASE_RESULTS_DIR, folder_name)

    if not os.path.isdir(folder_path):
        return {"error": True, "message": f"Folder not found: {folder_path}"}

    # جمع كل URLs من الملفات
    collected_urls = []
    for filename in os.listdir(folder_path):
        if filename.endswith(".json") or filename.endswith(".txt"):
            collected_urls.extend(extract_urls_from_file(os.path.join(folder_path, filename)))

    collected_urls = [url for url in set(collected_urls) if not is_static(url)]

    # تحديد كل URL باستخدام Selenium + detectors
    results = []
    max_workers = min(8, os.cpu_count() or 4)  # عدم فتح كثير Chrome

    def worker(url):
        try:
            detected = identify_page(url)
            return {"url": url, "detected": detected}
        except Exception as e:
            return {"url": url, "detected": [], "error": str(e)}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker, u) for u in collected_urls]
        for f in as_completed(futures):
            results.append(f.result())

    # حفظ النتائج في folder page_identifier
    os.makedirs(PAGE_IDENTIFIER_RESULTS_DIR, exist_ok=True)
    output_file = os.path.join(PAGE_IDENTIFIER_RESULTS_DIR, f"{domain.replace('.', '_')}_pages.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return {"domain": domain, "total_urls": len(collected_urls), "results_file": output_file}

# ===============================================
# Flask route
# ===============================================
@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    if not data or "domain" not in data:
        return jsonify({"error": "Missing 'domain' in JSON"}), 400
    return jsonify(process_domain(data["domain"]))

# ===============================================
# Run Flask
# ===============================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5009, debug=False)
