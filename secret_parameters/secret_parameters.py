from flask import Flask, request, jsonify
import os
import re
import subprocess
import shutil
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

app = Flask(__name__)

# ======================================================
# CLEAN ARJUN RESULTS FOLDER
# ======================================================
def cleanup_arjun_folder():
    folder = os.path.join(os.getcwd(), "arjun_results")
    if os.path.isdir(folder):
        try:
            shutil.rmtree(folder)
        except Exception:
            pass

# ======================================================
# CLEAN ARJUN STDOUT
# ======================================================
def clean_stdout(raw):
    cleaned = []
    for line in raw.splitlines():
        line_strip = line.strip()
        if line_strip.startswith("_"):
            continue
        if any(skip in line_strip for skip in [
            "Processing chunks",
            "Probing the target",
            "Analysing HTTP response",
            "Logicforcing",
            "Scanning "
        ]):
            continue
        if line_strip == "":
            continue
        cleaned.append(line_strip)
    if not cleaned:
        return "No parameters were discovered."
    return "\n".join(cleaned)

# ======================================================
# EXTRACT FINAL PARAMETERS — remove "based on:*"
# ======================================================
def extract_parameters(stdout_text):
    params = []
    for line in stdout_text.splitlines():
        line_strip = line.strip().lower()
        if line_strip.startswith("parameters found:") or line_strip.startswith("parameter detected:"):
            parts = line_strip.split(":", 1)
            if len(parts) > 1:
                raw_params = parts[1].split(",")
                for p in raw_params:
                    p = p.strip()
                    if not p:
                        continue
                    if p.lower().startswith("based on"):
                        continue
                    params.append(p)
    return params

# ======================================================
# INSTALL ARJUN IF NOT FOUND
# ======================================================
ARJUN_INSTALLED = False
def ensure_arjun():
    global ARJUN_INSTALLED
    if ARJUN_INSTALLED:
        return
    if shutil.which("arjun") is None:
        os.system("pip install arjun")
    if shutil.which("arjun") is None:
        raise Exception("Arjun installation failed!")
    ARJUN_INSTALLED = True

# ======================================================
# SAVE ARJUN OUTPUT TO FILE
# ======================================================
def save_arjun_output(url, stdout_text, stderr_text):
    BASE_SAVE = os.path.join(os.getcwd(), "arjun_results")
    os.makedirs(BASE_SAVE, exist_ok=True)
    safe_name = url.replace("https://", "").replace("http://", "")
    safe_name = re.sub(r'[^0-9a-zA-Z_]', '_', safe_name)
    filepath = os.path.join(BASE_SAVE, f"{safe_name}.txt")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("URL: " + url + "\n\n")
        f.write("=== STDOUT ===\n")
        f.write(stdout_text + "\n\n")
        f.write("=== STDERR ===\n")
        f.write(stderr_text + "\n")
    return filepath

# ======================================================
# RUN ARJUN — return ONLY urls with parameters, retry on errors
# ======================================================
def run_arjun(url, max_retries=2):
    for attempt in range(max_retries):
        try:
            cmd = ["arjun", "-u", url]
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            stdout_raw = proc.stdout.decode(errors="ignore")
            stderr_text = proc.stderr.decode(errors="ignore")

            stdout_text = clean_stdout(stdout_raw)
            parameters = extract_parameters(stdout_text)

            save_arjun_output(url, stdout_text, stderr_text)

            # ignore URLs without parameters
            if len(parameters) == 0:
                return None

            # retry if stdout contains "Extracted X parameters" but error exists
            if "Extracted" in stdout_raw and len(parameters) > 0 and stderr_text:
                time.sleep(1)  # short delay before retry
                continue

            return {
                "url": url,
                "parameters": parameters
            }

        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            return {
                "url": url,
                "parameters": [],
                "error": str(e)
            }

# ======================================================
# PARSE 200/500 URLS FROM FILE
# ======================================================
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

# ======================================================
# IGNORE STATIC FILES
# ======================================================
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

# ======================================================
# PROCESS DOMAIN — only keep endpoints with params
# ======================================================
def process_domain(domain):

    cleanup_arjun_folder()
    ensure_arjun()

    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
    BASE_RESULTS_DIR = os.path.join(PROJECT_ROOT, "directory_search", "results")

    folder_name = domain.replace(".", "_")
    folder_path = os.path.join(BASE_RESULTS_DIR, folder_name)

    if not os.path.isdir(folder_path):
        return {"error": True, "message": f"Folder not found: {folder_path}"}

    collected_urls = []
    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):
            collected_urls.extend(
                extract_urls_from_file(os.path.join(folder_path, filename))
            )

    collected_urls = [url for url in set(collected_urls) if not is_static(url)]

    results = []
    max_workers = os.cpu_count() or 4

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(run_arjun, url): url for url in collected_urls}
        for future in as_completed(future_to_url):
            try:
                r = future.result()
                if r:  # only if parameters exist
                    results.append(r)
            except Exception as e:
                results.append({
                    "url": future_to_url[future],
                    "error": str(e)
                })

    final_data = {
        "domain": domain,
        "total_urls": len(collected_urls),
        "results": results
    }

    # ======================================================
    # SAVE FINAL RESULTS TO FILE (BASED ON DOMAIN)
    # ======================================================
    safe_domain_name = domain.replace(".", "_")
    output_file = os.path.join(os.getcwd(), f"{safe_domain_name}_results.txt")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(final_data, f, indent=2)

    return final_data

# ======================================================
# FLASK ROOT
# ======================================================
@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    if not data or "domain" not in data:
        return jsonify({"error": "Missing 'domain' in JSON"}), 400
    return jsonify(process_domain(data["domain"]))

# ======================================================
# RUN
# ======================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004, debug=False)
