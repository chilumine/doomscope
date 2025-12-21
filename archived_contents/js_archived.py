from flask import Flask, request, jsonify
import requests
import re
from urllib.parse import urlparse

app = Flask(__name__)

# ==========================================================
# HELPERS
# ==========================================================
def fetch_wayback_urls(domain):
    url = (
        "http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
    )
    r = requests.get(url, timeout=30)
    return list(set(r.text.splitlines()))

def normalize_js_url(js_url):
    """
    Remove query string so:
    file.js?v=1 -> file.js
    """
    parsed = urlparse(js_url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

def extract_js_urls(urls):
    js_regex = re.compile(r"\.js(\?.*)?$", re.IGNORECASE)

    unique_js = {}
    for url in urls:
        if not js_regex.search(url):
            continue

        normalized = normalize_js_url(url)

        # keep first occurrence only
        if normalized not in unique_js:
            unique_js[normalized] = url

    # return normalized URLs only (clean)
    return sorted(unique_js.keys())

def save_js_file(domain, js_urls):
    filename = f"archived_js_files_{domain.replace('.', '_')}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        for url in js_urls:
            f.write(url + "\n")
    return filename

# ==========================================================
# API
# ==========================================================
@app.route("/scan", methods=["POST"])
def archive_js():
    data = request.json
    domain = data.get("domain")

    if not domain:
        return jsonify({"error": "domain is required"}), 400

    urls = fetch_wayback_urls(domain)
    js_urls = extract_js_urls(urls)
    saved_file = save_js_file(domain, js_urls)

    return jsonify({
        "domain": domain,
        "total_wayback_urls": len(urls),
        "total_unique_js_files": len(js_urls),
        "saved_file": saved_file,
        "js_files": js_urls
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9557, debug=True)
