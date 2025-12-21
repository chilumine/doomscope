from flask import Flask, request, jsonify
import os
import re
import json
import time
import shutil
import subprocess
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

TIMEOUT = 6

# ======================================================
# ENDPOINT CLEANER CONFIG
# ======================================================
BAD_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".ico", ".woff", ".woff2", ".ttf",
    ".map", ".pdf", ".zip", ".json"
)

BAD_KEYWORDS = (
    "/wp-", "/wp-content", "/wp-json",
    "/page/", "/tag/", "/category/",
    "/blog", "/blogs"
)


def looks_like_blog(path):
    return path.count("-") >= 2


def is_valid_endpoint(url):
    parsed = urlparse(url)
    path = parsed.path.lower()

    if not path or path == "/":
        return False

    if path.endswith(BAD_EXTENSIONS):
        return False

    for bad in BAD_KEYWORDS:
        if bad in path:
            return False

    if looks_like_blog(path):
        return False

    return True


def check_status(url):
    try:
        r = requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        return r.status_code
    except Exception:
        return None


# ======================================================
# ARJUN HELPERS
# ======================================================
def cleanup_arjun_folder():
    folder = os.path.join(os.getcwd(), "arjun_results")
    if os.path.isdir(folder):
        shutil.rmtree(folder, ignore_errors=True)


ARJUN_INSTALLED = False
def ensure_arjun():
    global ARJUN_INSTALLED
    if ARJUN_INSTALLED:
        return
    if shutil.which("arjun") is None:
        os.system("pip install arjun")
    if shutil.which("arjun") is None:
        raise Exception("Arjun install failed")
    ARJUN_INSTALLED = True


def clean_stdout(raw):
    cleaned = []
    for line in raw.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("_"):
            continue
        if any(x in s for x in [
            "Processing chunks", "Probing the target",
            "Analysing HTTP response", "Logicforcing", "Scanning"
        ]):
            continue
        cleaned.append(s)
    return "\n".join(cleaned)


def extract_parameters(stdout):
    params = []
    for line in stdout.splitlines():
        l = line.lower()
        if "parameter" in l and ":" in l:
            _, p = l.split(":", 1)
            for x in p.split(","):
                x = x.strip()
                if x and not x.startswith("based on"):
                    params.append(x)
    return list(set(params))


def run_arjun(url):
    try:
        proc = subprocess.run(
            ["arjun", "-u", url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        stdout_raw = proc.stdout.decode(errors="ignore")
        stdout_clean = clean_stdout(stdout_raw)
        params = extract_parameters(stdout_clean)

        if not params:
            return None

        return {
            "url": url,
            "parameters": params
        }

    except Exception as e:
        return {
            "url": url,
            "error": str(e)
        }


# ======================================================
# MAIN DOMAIN PROCESS
# ======================================================
def process_domain(domain):
    base_file = os.path.join(
        os.getcwd(),
        "api_results",
        domain,
        "aggregate.json"
    )

    if not os.path.isfile(base_file):
        return {"error": f"aggregate.json not found for {domain}"}

    with open(base_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    # =============================
    # STEP 1 — CLEAN ENDPOINTS
    # =============================
    alive_urls = []

    for item in data.get("results", []):
        for api in item.get("api_endpoints", []):
            url = api.get("endpoint")
            if not url:
                continue

            if is_valid_endpoint(url):
                status = check_status(url)
                if status in (200, 500):
                    alive_urls.append(url)

    alive_urls = list(set(alive_urls))

    # =============================
    # STEP 2 — ARJUN SCAN
    # =============================
    cleanup_arjun_folder()
    ensure_arjun()

    results = []
    max_workers = os.cpu_count() or 4

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(run_arjun, url): url for url in alive_urls}
        for f in as_completed(futures):
            r = f.result()
            if r:
                results.append(r)

    # =============================
    # STEP 3 — SAVE OUTPUT
    # =============================
    os.makedirs("public_parameters", exist_ok=True)
    out_file = os.path.join("public_parameters", f"{domain}.txt")

    final = {
        "domain": domain,
        "total_alive_endpoints": len(alive_urls),
        "endpoints_with_parameters": results
    }

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(final, f, indent=2)

    return final


# ======================================================
# FLASK ROUTE
# ======================================================
@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    if not data or "domain" not in data:
        return jsonify({"error": "missing domain"}), 400

    return jsonify(process_domain(data["domain"]))


# ======================================================
# RUN
# ======================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6666, debug=False)
