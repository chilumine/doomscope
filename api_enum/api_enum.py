#!/usr/bin/env python3
import subprocess
import json
import re
from pathlib import Path
from urllib.parse import urljoin
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

SCAN_SERVICE = "http://127.0.0.1:5000/scan"


# =========================================================
# FETCH SUBDOMAINS
# =========================================================
def fetch_subdomains(domain):
    payload = {"domain": domain, "sources": ["crt.sh", "root", "sublist3r", "wayback_urls"]}
    headers = {"Content-Type": "application/json"}

    r = requests.post(SCAN_SERVICE, json=payload, headers=headers, timeout=None)
    r.raise_for_status()

    data = r.json()
    subs = []

    if isinstance(data, dict) and "subdomains" in data:
        if isinstance(data["subdomains"], dict):
            subs = list(data["subdomains"].keys())
        else:
            subs = data["subdomains"]
    elif isinstance(data, list):
        subs = data
    else:
        for k in data.keys():
            if "." in k:
                subs.append(k)

    return sorted(set([s.strip() for s in subs if s]))


# =========================================================
# ENUM API
# =========================================================
def enum_api(url):
    domain_only = re.sub(r"https?://", "", url).strip("/")

    output_file = Path("output.txt")
    if output_file.exists():
        output_file.unlink()

    cmd = ["xnlinkfinder", "-i", url, "-sf", domain_only]
    proc = subprocess.run(cmd, capture_output=True, text=True)

    raw_output = proc.stdout.strip()
    if not raw_output:
        return []

    apis = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("http://") or line.startswith("https://"):
            full_url = line
        else:
            full_url = urljoin(f"https://{domain_only}", line)
        apis.append(full_url)

    return sorted(set(apis))


# =========================================================
# ENABLED METHODS
# =========================================================
def get_enabled_methods(endpoint):
    try:
        r = requests.options(endpoint, timeout=5)
        allow = r.headers.get("Allow", "")
        return [m.strip() for m in allow.split(",")] if allow else ["unknown"]
    except:
        return ["Error"]


# =========================================================
# NORMALIZE
# =========================================================
def normalize(name):
    name = re.sub(r"https?://", "", name)
    return name.replace("/", "_").replace(":", "_").strip("_")


# =========================================================
# FLASK ROUTE
# =========================================================
@app.route("/run", methods=["POST"])
def run_api_enum_service():
    body = request.get_json(force=True)

    if not body or "domain" not in body:
        return jsonify({"error": "Provide JSON: {\"domain\": \"example.com\"}"}), 400

    root_domain = body["domain"].strip()

    # Fetch subdomains
    subdomains = fetch_subdomains(root_domain)

    base_folder = Path("api_results") / normalize(root_domain)
    base_folder.mkdir(parents=True, exist_ok=True)

    results = []

    for sub in subdomains:
        url = f"https://{sub}"

        api_list = enum_api(url)

        sub_data = []
        for ep in api_list:
            methods = get_enabled_methods(ep)
            sub_data.append({"endpoint": ep, "methods": methods})

        # save per-subdomain json
        sub_folder = base_folder / normalize(sub)
        sub_folder.mkdir(exist_ok=True)
        with open(sub_folder / "api.json", "w", encoding="utf-8") as f:
            json.dump({"subdomain": sub, "api_endpoints": sub_data}, f, indent=4)

        results.append({"subdomain": sub, "api_endpoints": sub_data})

    # save aggregate
    with open(base_folder / "aggregate.json", "w", encoding="utf-8") as f:
        json.dump({"root_domain": root_domain, "results": results}, f, indent=4)

    return jsonify({
        "root_domain": root_domain,
        "total_subdomains": len(subdomains),
        "results": results
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8002, debug=True)
