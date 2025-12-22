from flask import Flask, request, jsonify
import requests
import json
from urllib.parse import urlparse, parse_qs

app = Flask(__name__)

INTERESTING_PARAMS = [
    "redirect", "redirect_url", "redirecturi", "return", "return_url",
    "next", "continue", "dest", "destination", "callback", "cb", "url",
    "token", "access_token", "auth", "session", "jwt", "key", "apikey", "api_key",
    "target", "to", "out", "host", "domain", "uri",
    "file", "path", "view", "doc", "download", "page", "template",
    "msg", "message", "error", "err", "status", "reason", "debug",
    "alert", "search", "query", "q", "s", "keyword",
    "id", "uid", "user_id", "account", "order", "order_id",
    "item", "item_id", "category", "type", "sort"
]

# ==========================================================
# HELPERS
# ==========================================================
def fetch_wayback_urls(domain):
    url = (
        "http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
    )
    r = requests.get(url)
    return list(set(r.text.splitlines()))

def extract_interesting_params(url):
    parsed = urlparse(url)
    if not parsed.query:
        return []

    params = parse_qs(parsed.query)
    matched = set()

    for p in params.keys():
        for keyword in INTERESTING_PARAMS:
            if keyword in p.lower():
                matched.add(p)

    return list(matched)

def save_results(domain, data):
    filename = f"archived_parameters_{domain.replace('.', '_')}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return filename

# ==========================================================
# API
# ==========================================================
@app.route("/scan", methods=["POST"])
def scan_params():
    data = request.json
    domain = data.get("domain")

    if not domain:
        return jsonify({"error": "domain is required"}), 400

    urls = fetch_wayback_urls(domain)

    # ✅ parameter -> endpoint (keep first only)
    parameter_map = {}

    for url in urls:
        if "?" not in url:
            continue

        base_url = url.split("?")[0]
        matched_params = extract_interesting_params(url)

        for p in matched_params:
            if p not in parameter_map:
                parameter_map[p] = base_url

    # 🔁 build final output
    results = [
        {
            "url": endpoint,
            "parameters": [param]
        }
        for param, endpoint in parameter_map.items()
    ]

    output = {
        "domain": domain,
        "total_urls": len(results),
        "results": results
    }

    saved_file = save_results(domain, output)

    return jsonify({
        **output,
        "saved_file": saved_file
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9565, debug=True)
