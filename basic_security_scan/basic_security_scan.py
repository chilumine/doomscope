#!/usr/bin/env python3
import os
import sys
import json
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from flask import Flask, request, jsonify

# =====================
# Config
# =====================
SCAN_SERVICE = "http://127.0.0.1:5000/scan"
RESULTS_DIR = Path("./nuclei_results")
MAX_WORKERS = 6
NUCLEI_TEMPLATES = [
    "nuclei-templates/http/cves/",
    "nuclei-templates/http/vulnerabilities/",
    "nuclei-templates/http/misconfiguration/",
    "nuclei-templates/http/default-logins/",
    "nuclei-templates/http/exposures/",
    "nuclei-templates/http/technologies/"
]

app = Flask(__name__)

# =====================
# Helpers
# =====================

def check_installed(cmd):
    return shutil.which(cmd) is not None

def remove_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def format_id(tid):
    if tid.upper().startswith("CVE-"):
        return tid
    if ":" in tid:
        left, right = tid.split(":", 1)
        return f"{left.replace('-', ' ')} ({right.replace('-', ' ')})"
    return tid.replace("-", " ")

def parse_nuclei_output(raw_file):
    findings = []
    with open(raw_file, "r", encoding="utf-8") as f:
        for line in f:
            line = remove_ansi_codes(line.strip())
            m = re.match(r'\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+(https?://\S+)(.*)', line)
            if not m:
                continue
            template_id = m.group(1).strip()
            protocol = m.group(2).strip()
            severity = m.group(3).strip()
            host = m.group(4).strip()
            extra = m.group(5).strip()

            extracted = []
            if "[" in extra and "]" in extra:
                try:
                    extracted = json.loads(extra[extra.index("["):])
                except:
                    extracted = []

            findings.append({
                "id": format_id(template_id),
                "severity": severity,
                "protocol": protocol,
                "host": host,
                "extracted": extracted
            })
    return findings


# =====================
# Fetch subdomains first
# =====================
def fetch_subdomains(domain):
    payload = {"domain": domain, "sources": ["crt.sh", "root", "sublist3r", "wayback_urls"]}
    r = requests.post(SCAN_SERVICE, json=payload, timeout=None)
    r.raise_for_status()
    data = r.json()

    subs = []
    if isinstance(data, dict) and "subdomains" in data:
        subs = list(data["subdomains"].keys())

    subs = sorted(set(subs))
    return subs


# =====================
# Run nuclei on a single host
# =====================
def run_nuclei_on_host(host, out_path):
    """Execute nuclei for a single target and return parsed findings."""
    cmd = ["nuclei", "-u", host]

    for t in NUCLEI_TEMPLATES:
        cmd += ["-t", t]

    raw_file = out_path / "nuclei_raw.txt"
    raw_file.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(raw_file, "w", encoding="utf-8") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, text=True)
    except Exception as e:
        return {"host": host, "error": str(e)}

    findings = parse_nuclei_output(raw_file)
    return {
        "host": host,
        "total_findings": len(findings),
        "findings": findings,
        "raw_output_file": str(raw_file)
    }


# =====================
# Flask Endpoint
# =====================
@app.route("/run", methods=["POST"])
def run():
    body = request.get_json(force=True)
    if "domain" not in body:
        return jsonify({"error": "send: {\"domain\": \"example.com\"}"}), 400

    domain = body["domain"]

    # 1) Fetch subdomains
    try:
        subs = fetch_subdomains(domain)
    except Exception as e:
        return jsonify({"error": "failed to fetch subdomains", "detail": str(e)}), 500

    if not subs:
        return jsonify({"error": "no subdomains found"}), 400

    RESULTS_DIR.mkdir(exist_ok=True)
    out_dir = RESULTS_DIR / domain.replace(".", "_")
    out_dir.mkdir(exist_ok=True)

    # 2) Run nuclei on them in parallel
    results = []
    futures = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for sub in subs:
            host = "https://" + sub
            host_dir = out_dir / host.replace("://", "_")
            futures.append(ex.submit(run_nuclei_on_host, host, host_dir))

        for f in as_completed(futures):
            results.append(f.result())

    return jsonify({
        "domain": domain,
        "total_subdomains": len(subs),
        "results": results
    })


if __name__ == "__main__":
    if not check_installed("nuclei"):
        print("[ERROR] nuclei is not installed!", file=sys.stderr)
        sys.exit(1)

    app.run(host="0.0.0.0", port=8001, debug=True)
