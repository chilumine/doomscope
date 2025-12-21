from flask import Flask, request, jsonify
import os
import re
import json
import sys
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init

init(autoreset=True)

app = Flask(__name__)

DETECTORS_DIR = "detectors"
PAGE_IDENTIFIER_RESULTS_DIR = "public_page_identifier"

# ===============================================
# Silent Chrome
# ===============================================
def silent_chrome_options():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--log-level=3")
    options.add_experimental_option("excludeSwitches", ["enable-logging"])
    return options

# ===============================================
# Load detectors
# ===============================================
def load_detectors():
    detectors = []
    for f in os.listdir(DETECTORS_DIR):
        if f.endswith(".json"):
            with open(os.path.join(DETECTORS_DIR, f), encoding="utf-8") as fd:
                detectors.append(json.load(fd))
    return detectors

# ===============================================
# HTML scoring
# ===============================================
def check_html_signals(soup, detector):
    score = 0
    html = detector.get("html", {})
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

def check_text_signals(text, detector):
    score = 0
    t = detector.get("text", {})
    for w in t.get("required", []):
        if w.lower() in text:
            score += detector["scoring"].get("text_required", 0)
    for w in t.get("optional", []):
        if w.lower() in text:
            score += detector["scoring"].get("text_optional", 0)
    for w in t.get("forbidden", []):
        if w.lower() in text:
            score += detector["scoring"].get("forbidden_penalty", 0)
    return score

def analyze_page(html, detector):
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ").lower()
    score = check_html_signals(soup, detector) + check_text_signals(text, detector)
    if score >= detector.get("logic", {}).get("min_total_score", 1):
        return detector["name"]
    return None

# ===============================================
# Selenium page identify
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
        r = analyze_page(html, d)
        if r:
            matches.append(r)
    return matches

# ===============================================
# Filters
# ===============================================
def is_static_or_useless(url):
    bad_ext = (
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
        ".svg", ".woff", ".ttf", ".ico",
        ".zip", ".pdf", ".txt", ".log"
    )
    bad_keywords = (
        "/blog", "/static", "/assets", "/images",
        "sitemap", "robots.txt"
    )

    u = url.lower()
    if any(u.endswith(ext) for ext in bad_ext):
        return True
    if any(k in u for k in bad_keywords):
        return True
    return False

# ===============================================
# Load URLs from aggregate.json
# ===============================================
def load_urls_from_api_enum(domain):
    base = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "api_enum", "api_results")
    )

    path = os.path.join(base, domain, "aggregate.json")
    if not os.path.isfile(path):
        return None, f"aggregate.json not found: {path}"

    urls = []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    for entry in data.get("results", []):
        for ep in entry.get("api_endpoints", []):
            url = ep.get("endpoint")
            if url and not is_static_or_useless(url):
                urls.append(url)

    return sorted(set(urls)), None

# ===============================================
# Main domain processing
# ===============================================
def process_domain(domain):
    urls, err = load_urls_from_api_enum(domain)
    if err:
        return {"error": True, "message": err}

    results = []
    max_workers = min(8, os.cpu_count() or 4)

    def worker(url):
        try:
            return {
                "url": url,
                "detected": identify_page(url)
            }
        except Exception as e:
            return {
                "url": url,
                "detected": [],
                "error": str(e)
            }

    with ThreadPoolExecutor(max_workers=max_workers) as exe:
        futures = [exe.submit(worker, u) for u in urls]
        for f in as_completed(futures):
            results.append(f.result())

    os.makedirs(PAGE_IDENTIFIER_RESULTS_DIR, exist_ok=True)
    outfile = os.path.join(
        PAGE_IDENTIFIER_RESULTS_DIR,
        f"{domain.replace('.', '_')}_pages.json"
    )

    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return {
        "domain": domain,
        "total_urls": len(urls),
        "results_file": outfile
    }

# ===============================================
# Flask
# ===============================================
@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    if not data or "domain" not in data:
        return jsonify({"error": "Missing domain"}), 400
    return jsonify(process_domain(data["domain"]))

# ===============================================
# Run
# ===============================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5109, debug=False)
