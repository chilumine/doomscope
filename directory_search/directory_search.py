#!/usr/bin/env python3
"""
Flask service: orchestrate dirsearch against subdomains obtained from a local scan service.

Usage:
  1) Install deps:
     python3 -m pip install -r requirements.txt

  2) Run:
     python3 app.py

  3) Call:
     POST http://127.0.0.1:8000/run
     Body JSON: {"domain":"inisev.com"}
     OR: {"subdomains":["a.example.com","b.example.com"]}

Outputs:
  - Aggregated JSON response (in HTTP response)
  - Per-host JSON files in ./results/<domain_or_custom>/host.json
"""

import os
import sys
import json
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from time import time

import requests
from flask import Flask, request, jsonify

# --- config ---
SCAN_SERVICE = "http://127.0.0.1:5000/scan"
TOOLS_DIR = Path("./tools")
DIRSEARCH_GIT = "https://github.com/maurosoria/dirsearch.git"
DIRSEARCH_PATH = TOOLS_DIR / "dirsearch"
RESULTS_DIR = Path("./results")
MAX_WORKERS = 6
DIRSEARCH_TIMEOUT = None  # no limit
DIRSEARCH_EXTS = "php,html,js,txt,json,xml,env,log"
DIRSEARCH_WORDLIST = None

app = Flask(__name__)

def ensure_psycopg():
    """Ensure psycopg is installed."""
    try:
        import psycopg  # noqa: F401
    except ModuleNotFoundError:
        print("[*] psycopg not found, installing...", file=sys.stderr)
        subprocess.check_call([sys.executable, "-m", "pip", "install", "psycopg"])

def install_dirsearch_requirements():
    """Install requirements.txt of dirsearch if exists."""
    req_file = DIRSEARCH_PATH / "requirements.txt"
    if req_file.exists():
        print("[*] Installing dirsearch requirements...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(req_file)])

def ensure_dirsearch():
    """Ensure dirsearch is available. Clone if not found and install deps."""
    ensure_psycopg()  # make sure psycopg is installed

    if shutil.which("dirsearch"):
        return (["dirsearch"], "cli")

    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    if not DIRSEARCH_PATH.exists():
        app.logger.info(f"Cloning dirsearch into {DIRSEARCH_PATH} ...")
        try:
            subprocess.check_call(["git", "clone", "--depth", "1", DIRSEARCH_GIT, str(DIRSEARCH_PATH)])
        except Exception as e:
            raise RuntimeError(f"dirsearch not installed and git clone failed: {e}")

    # Install requirements after clone
    install_dirsearch_requirements()

    script = DIRSEARCH_PATH / "dirsearch.py"
    if not script.exists():
        raise RuntimeError("dirsearch repo found but dirsearch.py missing")

    return ([sys.executable, str(script)], "git-clone")

def run_dirsearch_for_host(runner_cmd, host, out_json_path, timeout=DIRSEARCH_TIMEOUT):
    """Run dirsearch for one host."""
    cmd = list(runner_cmd)
    cmd += ["-u", host, "-o", str(out_json_path)]
    if DIRSEARCH_EXTS:
        cmd += ["-e", DIRSEARCH_EXTS]
    if DIRSEARCH_WORDLIST:
        cmd += ["-l", DIRSEARCH_WORDLIST]

    start = time()
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True)
        elapsed = time() - start
        parsed = None
        if out_json_path.exists():
            try:
                parsed = json.loads(out_json_path.read_text(encoding="utf-8"))
            except Exception:
                parsed = None
        return {
            "host": host,
            "cmd": cmd,
            "returncode": proc.returncode,
            "stdout": proc.stdout[:2000],
            "stderr": proc.stderr[:2000],
            "elapsed": elapsed,
            "json": parsed,
            "json_path": str(out_json_path) if out_json_path.exists() else None,
        }
    except subprocess.TimeoutExpired:
        return {"host": host, "cmd": cmd, "error": "timeout", "timeout_seconds": timeout}
    except Exception as e:
        return {"host": host, "cmd": cmd, "error": str(e)}

def fetch_subdomains_from_scan_service(domain):
    """Call the local scan service (no timeout limit)."""
    payload = {"domain": domain, "sources": ["crt.sh", "root", "sublist3r", "wayback_urls"]}
    headers = {"Content-Type": "application/json"}
    r = requests.post(SCAN_SERVICE, json=payload, headers=headers, timeout=None)
    r.raise_for_status()
    data = r.json()

    subs = []
    if isinstance(data, dict) and "subdomains" in data:
        for k in data["subdomains"].keys():
            subs.append(k)
    elif isinstance(data, dict) and isinstance(data.get("subdomains"), list):
        subs = data["subdomains"]
    elif isinstance(data, list):
        subs = data
    else:
        for k in data.keys():
            if isinstance(k, str) and "." in k:
                subs.append(k)
    subs = sorted(set([s.strip() for s in subs if s and "." in s]))
    return subs

@app.route("/run", methods=["POST"])
def run():
    """POST body: {"domain":"inisev.com"} OR {"subdomains":["a.inisev.com", ...]}"""
    body = request.get_json(force=True)
    if body is None:
        return jsonify({"error": "bad json body"}), 400

    subdomains = []
    label = None

    if "subdomains" in body:
        if not isinstance(body["subdomains"], list):
            return jsonify({"error": "subdomains must be a list"}), 400
        subdomains = body["subdomains"]
        label = body.get("label", "custom")

    elif "domain" in body:
        domain = body["domain"]
        label = body.get("label", domain.replace(".", "_"))
        try:
            subdomains = fetch_subdomains_from_scan_service(domain)
        except Exception as e:
            return jsonify({"error": "scan service call failed", "detail": str(e)}), 500
    else:
        return jsonify({"error": "provide 'domain' or 'subdomains' in body"}), 400

    if not subdomains:
        return jsonify({"error": "no subdomains found"}), 400

    out_base = RESULTS_DIR / label
    out_base.mkdir(parents=True, exist_ok=True)

    try:
        runner_cmd, runner_type = ensure_dirsearch()
    except Exception as e:
        return jsonify({"error": "dirsearch not available and could not be installed", "detail": str(e)}), 500

    results = []
    futures = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for host in subdomains:
            safe_host = host.replace("://", "").replace("/", "_")
            out_file = out_base / f"{safe_host}.json"
            futures.append(ex.submit(run_dirsearch_for_host, runner_cmd, host if host.startswith("http") else f"https://{host}", out_file))

        for f in as_completed(futures):
            try:
                res = f.result()
            except Exception as e:
                res = {"error": str(e)}
            results.append(res)

    summary = {
        "label": label,
        "total_targets": len(subdomains),
        "successful_runs": sum(1 for r in results if r.get("json") is not None),
        "results": results,
    }

    return jsonify(summary)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
