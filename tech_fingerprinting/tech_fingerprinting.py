#!/usr/bin/env python3
"""
Robust Flask service: Subdomain tech scanner
- Queries subdomain enumeration service at http://127.0.0.1:5000/scan (no timeout)
- For each discovered hostname:
    * filters-out invalid entries (emails / non-hosts)
    * tries HTTPS then HTTP using requests (verify=False) to bypass SSL issues
    * marks "exists" if reachable (HTTP status < 400)
    * passes HTML to Wappalyzer via WebPage.new_from_string() to detect technologies
- Uses ThreadPoolExecutor to parallelize host scans
- Returns clear JSON:
    {
      "domain": "...",
      "sources": [...],
      "subdomains": {
         "a.example.com": {
             "sources": [...],
             "exists": true,
             "status_code": 200,
             "technologies": { ... }
         }, ...
      }
    }
"""

import sys
import subprocess
import json
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----- helper to install missing packages at runtime ----- #
def pip_install(pkg):
    cmd = [sys.executable, "-m", "pip", "install", pkg]
    subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# ensure requests
try:
    import requests
except Exception:
    pip_install("requests")
    import requests

# ensure python-Wappalyzer
try:
    from Wappalyzer import Wappalyzer, WebPage
except Exception:
    pip_install("python-Wappalyzer")
    from Wappalyzer import Wappalyzer, WebPage

# ensure flask
try:
    from flask import Flask, request, jsonify
except Exception:
    pip_install("flask")
    from flask import Flask, request, jsonify

# ---------------- app config ---------------- #
app = Flask(__name__)
SUBDOMAIN_ENUM_ENDPOINT = "http://127.0.0.1:5000/scan"

# concurrency settings
MAX_WORKERS = 10

# small validators / helpers
def is_valid_host(name, base_domain):
    """Return True if name looks like a host and ends with base_domain. Exclude emails."""
    if not name or "@" in name:
        return False
    n = name.strip()
    if "." not in n:
        return False
    # ensure it ends with base domain (exact or subdomain)
    return n.endswith(base_domain)

def fetch_host_response(hostname, connect_timeout=10, read_timeout=15):
    """
    Try HTTPS then HTTP using requests.get(..., verify=False).
    Returns: (response_or_None, used_url_or_None, err_or_None)
    """
    schemes = ("https://", "http://")
    last_err = None
    for scheme in schemes:
        url = scheme + hostname
        try:
            # allow redirects, ignore SSL verification
            r = requests.get(url, timeout=(connect_timeout, read_timeout), allow_redirects=True, verify=False)
            return r, url, None
        except Exception as e:
            last_err = e
            continue
    return None, None, last_err

def analyze_html_with_wappalyzer(resp, url):
    """
    Given requests.Response and url, produce Wappalyzer technologies dict.
    We pass HTML to WebPage.new_from_string to avoid Wappalyzer internal fetching.
    """
    try:
        w = Wappalyzer.latest()
    except Exception as e:
        return {"error": f"wappalyzer_init_error: {str(e)}"}

    html = ""
    try:
        # prefer resp.text; but guard against None
        html = resp.text if resp is not None else ""
    except Exception:
        html = ""

    # Build WebPage using available API
    try:
        if hasattr(WebPage, "new_from_string"):
            webpage = WebPage.new_from_string(html, url)
        else:
            # fallback: try new_from_response (some versions)
            if hasattr(WebPage, "new_from_response"):
                webpage = WebPage.new_from_response(resp)
            else:
                webpage = WebPage.new_from_string(html, url)
    except Exception as e:
        return {"error": f"webpage_creation_failed: {str(e)}"}

    try:
        if hasattr(w, "analyze_with_categories"):
            techs = w.analyze_with_categories(webpage)
        else:
            # older API: analyze(...) returns list
            raw = w.analyze(webpage)
            if isinstance(raw, (list, tuple)):
                techs = {t: [] for t in raw}
            else:
                techs = raw if isinstance(raw, dict) else {"unknown": raw}
        return techs
    except Exception as e:
        return {"error": f"wappalyzer_analyze_failed: {str(e)}"}

def scan_single_host(hostname, sources, base_domain):
    """
    Full treatment for a single host:
      - validate hostname
      - fetch via HTTPS/HTTP (ignore SSL errors)
      - set exists flag and status_code
      - if exists, analyze HTML with Wappalyzer
    Returns tuple: (hostname, entry_dict)
    """
    entry = {"sources": sorted(list(sources))}
    # validate
    if not is_valid_host(hostname, base_domain):
        entry["exists"] = False
        entry["technologies"] = {"error": "invalid_hostname"}
        return hostname, entry

    # fetch
    resp, used_url, err = fetch_host_response(hostname)
    if resp is None:
        entry["exists"] = False
        entry["status_code"] = None
        entry["technologies"] = {"error": f"unreachable: {str(err)}"}
        return hostname, entry

    # mark exists and include status
    entry["exists"] = True
    entry["status_code"] = resp.status_code

    # If status code indicates failure (>=400) still try to analyze the body in case of error pages
    try:
        techs = analyze_html_with_wappalyzer(resp, used_url or f"http://{hostname}")
        entry["technologies"] = techs
    except Exception as e:
        entry["technologies"] = {"error": f"analysis_failed: {str(e)}"}

    return hostname, entry

@app.route("/techscan", methods=["POST"])
def techscan():
    payload = request.get_json(force=True)
    domain = payload.get("domain")
    if not domain:
        return jsonify({"error": "domain required"}), 400

    base_domain = domain.strip().lower()
    if base_domain.startswith("http://") or base_domain.startswith("https://"):
        from urllib.parse import urlparse
        base_domain = urlparse(base_domain).hostname or base_domain

    # 1) call subdomain enumeration service (no timeout as requested)
    try:
        resp = requests.post(SUBDOMAIN_ENUM_ENDPOINT, json={"domain": base_domain})
        if resp.status_code != 200:
            return jsonify({"error": "failed to get subdomains", "details": resp.text}), 500
        enum_data = resp.json()
    except Exception as e:
        return jsonify({"error": "failed to call subdomain service", "details": str(e)}), 500

    raw_subs = enum_data.get("subdomains", {})

    # 2) normalize & aggregate sources
    agg = defaultdict(set)  # host -> set(sources)
    for key, meta in raw_subs.items():
        name = str(key).strip()
        # skip obvious non-hosts (emails, lines containing 'AS', etc.)
        if "@" in name:
            continue
        # some crt.sh results include certificate subject lines / org names; require it to end with base_domain
        if not name.endswith(base_domain):
            continue
        # now pull sources
        if isinstance(meta, dict):
            sources = meta.get("sources", [])
            if isinstance(sources, str):
                sources = [sources]
        elif isinstance(meta, (list, tuple)):
            sources = list(meta)
        else:
            sources = []
        agg[name].update(sources)

    # ensure root domain present
    agg[base_domain].add("root")

    # collect overall sources
    all_sources = set()
    for s in agg.values():
        all_sources.update(s)

    # 3) scan hosts in parallel
    results = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        futures = {exe.submit(scan_single_host, host, agg[host], base_domain): host for host in agg.keys()}
        for fut in as_completed(futures):
            try:
                host, entry = fut.result()
            except Exception as e:
                host = futures[fut]
                entry = {"sources": sorted(list(agg[host])), "exists": False, "technologies": {"error": f"scan_crashed: {str(e)}"}}
            results[host] = entry

    # ------------------ Simplify output (user requested) ------------------
    # Build simple subdomains dict: include only reachable hosts (exists True)
    # For technologies, return a simple list of technology names (keys) when available.
    simplified_subs = {}
    for host, info in results.items():
        try:
            if not info.get("exists"):
                continue  # skip unreachable / invalid hosts
            # extract tech names
            techs = info.get("technologies", {})
            tech_names = []
            if isinstance(techs, dict):
                # ignore errors entries
                if "error" in techs:
                    tech_names = []
                else:
                    # keys are tech names
                    tech_names = list(techs.keys())
            elif isinstance(techs, list):
                tech_names = techs
            else:
                tech_names = []
            # include the host with sources and tech list (compact)
            simplified_subs[host] = {
                "sources": info.get("sources", []),
                "technologies": sorted(tech_names)
            }
        except Exception:
            # if anything fails, skip host to keep output clean
            continue

    final = {
        "domain": base_domain,
        "sources": sorted(list(all_sources)),
        "subdomains": simplified_subs
    }

    return jsonify(final), 200

if __name__ == "__main__":
    # run flask app
    app.run(host="0.0.0.0", port=6000)
