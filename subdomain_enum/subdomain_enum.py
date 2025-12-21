#!/usr/bin/env python3
"""
Subdomain Enumeration and Asset Discovery Service
Robust, cross-platform (Windows/Linux) single-file Flask service.
- Uses Python libraries (crt.sh, Wayback CDX, dnspython) as primary sources.
- Attempts to use sublist3r via subprocess (safer) or module as fallback.
- Protects against third-party library exceptions and returns helpful messages in JSON.
"""

import sys
import os
import subprocess
import shutil
import time
import json
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, jsonify

# ------------------ Utilities for Python package installation / Git fallback ------------------ #

def pip_install(package):
    """Install a pip package using the running python interpreter."""
    cmd = [sys.executable, "-m", "pip", "install", package]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc.returncode == 0, proc.stdout + proc.stderr

def git_clone(repo_url, dest_dir):
    """Clone repo_url into dest_dir using git if available."""
    git = shutil.which("git")
    if not git:
        return False, "git not found in PATH"
    if os.path.exists(dest_dir):
        return True, f"already cloned: {dest_dir}"
    cmd = [git, "clone", repo_url, dest_dir]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc.returncode == 0, proc.stdout + proc.stderr

def ensure_package_import(pkg_name, pip_name=None, git_fallback=None, module_name=None):
    """
    Ensure a Python package is importable.
    Returns (imported_module_or_None, msg)
    """
    try:
        mod = __import__(pkg_name)
        return mod, f"imported {pkg_name}"
    except Exception:
        pip_pkg = pip_name or pkg_name
        ok, out = pip_install(pip_pkg)
        if ok:
            try:
                mod = __import__(pkg_name)
                return mod, f"installed {pip_pkg} via pip"
            except Exception:
                pass
        if git_fallback:
            repo, sub = git_fallback
            tools_dir = os.path.join(os.getcwd(), "tools")
            os.makedirs(tools_dir, exist_ok=True)
            dest = os.path.join(tools_dir, os.path.basename(repo).replace(".git",""))
            ok_clone, out_clone = git_clone(repo, dest)
            if ok_clone:
                sys.path.insert(0, dest)
                try:
                    mod = __import__(pkg_name if not module_name else module_name)
                    return mod, f"cloned {repo} and imported"
                except Exception as e:
                    return None, f"cloned {repo} but import failed: {e}"
            else:
                return None, f"pip install failed and git clone failed: {out_clone}"
        return None, f"pip install failed: {out}"

# ------------------ Ensure required libraries ------------------ #

mods = {}
msgs = []

for pkg, pip_pkg in [("dns", "dnspython"), ("tldextract", "tldextract"), ("requests", "requests")]:
    m, msg = ensure_package_import(pkg, pip_pkg)
    mods[pkg] = m
    msgs.append(f"{pkg}: {msg}")

# Optional libraries
m, msg = ensure_package_import("waybackpy", "waybackpy")
mods["waybackpy"] = m
msgs.append(f"waybackpy: {msg}")

m, msg = ensure_package_import(
    "sublist3r",
    "Sublist3r",
    git_fallback=("https://github.com/aboul3la/Sublist3r.git", None),
    module_name="sublist3r"
)
mods["sublist3r"] = m
msgs.append(f"sublist3r: {msg}")

# ------------------ Recon helper functions ------------------ #

def get_crtsh_subdomains(domain):
    """Query crt.sh for certificate entries and extract hostnames."""
    import requests
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code != 200:
            return [], f"crt.sh status {r.status_code}"
        try:
            data = r.json()
        except Exception as e:
            return [], f"crt.sh json parse error: {e}"
        hosts = set()
        for entry in data:
            name = entry.get("name_value") or entry.get("common_name")
            if not name:
                continue
            for part in str(name).splitlines():
                part = part.strip()
                if part.endswith(domain):
                    part = part.lstrip("*.")  # remove wildcard
                    # Skip if it looks like an email
                    if "@" not in part:
                        hosts.add(part)
        return sorted(hosts), "ok"
    except Exception as e:
        return [], f"error: {e}"

COMMON_SUBS = [
    "www","mail","api","dev","test","staging","portal","admin","beta","m","shop",
    "smtp","secure","vpn","webmail","cpanel","git","gitlab","img","static"
]

def brute_subdomains(domain, timeout=3):
    """Simple DNS brute-force on common subdomains."""
    try:
        import dns.resolver
    except Exception:
        return []
    found = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    for s in COMMON_SUBS:
        fqdn = f"{s}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A")
            if answers:
                found.append(fqdn)
        except Exception:
            continue
    return found

def run_sublist3r(domain, timeout=60):
    """Run Sublist3r robustly: CLI > python -m > module fallback."""
    cli = shutil.which("sublist3r")
    if cli:
        try:
            proc = subprocess.run([cli, "-d", domain, "-o", "-"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=timeout, text=True)
            out = proc.stdout + proc.stderr
            subs = re.findall(r"[a-zA-Z0-9_\-\.]+\.%s" % re.escape(domain), out)
            subs = [s for s in subs if "@" not in s]
            return sorted(set(subs)), "sublist3r_cli_ok"
        except subprocess.TimeoutExpired:
            return [], "sublist3r_cli_timeout"
        except Exception as e:
            return [], f"sublist3r_cli_error:{e}"

    try:
        proc = subprocess.run([sys.executable, "-m", "sublist3r", "-d", domain, "-o", "-"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, text=True)
        out = proc.stdout + proc.stderr
        subs = re.findall(r"[a-zA-Z0-9_\-\.]+\.%s" % re.escape(domain), out)
        subs = [s for s in subs if "@" not in s]
        if subs:
            return sorted(set(subs)), "sublist3r_pythonm_ok"
    except subprocess.TimeoutExpired:
        return [], "sublist3r_pythonm_timeout"
    except Exception:
        pass

    try:
        import importlib.util
        spec = importlib.util.find_spec("sublist3r")
        if spec:
            try:
                sublist3r = importlib.import_module("sublist3r")
                if hasattr(sublist3r, "main"):
                    try:
                        result = sublist3r.main(domain, 40, None, ports=None, silent=True,
                                                verbose=False, enable_bruteforce=False, engines=None)
                        if isinstance(result, list):
                            result = [s for s in result if "@" not in s]
                            return sorted(set(result)), "sublist3r_module_ok"
                    except Exception:
                        pass
            except Exception:
                pass
    except Exception:
        pass

    return [], "sublist3r_not_available"

def wayback_urls_for_domain(domain, limit=500):
    """Use Wayback CDX API to fetch archived URLs for a domain."""
    import requests
    api = "http://web.archive.org/cdx/search/cdx"
    params = {"url": f"*.{domain}/*", "output":"json", "fl":"original",
              "filter":"statuscode:200", "limit":limit}
    try:
        r = requests.get(api, params=params, timeout=15)
        if r.status_code != 200:
            return [], f"cdx status {r.status_code}"
        data = r.json()
        urls = [row[0] for row in data[1:] if row]
        return sorted(set(urls)), "ok"
    except Exception as e:
        return [], f"error: {e}"

def http_check(url, timeout=6):
    """Check HTTP(S) status of a URL."""
    import requests
    try:
        r = requests.head(url, timeout=timeout, allow_redirects=True)
        return {"url": url, "status": r.status_code, "len": r.headers.get("content-length")}
    except Exception:
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True)
            return {"url": url, "status": r.status_code, "len": r.headers.get("content-length")}
        except Exception as e:
            return {"url": url, "status": None, "error": str(e)}

def resolve_host_check(hostname, timeout=3):
    """Resolve a host via DNS A/AAAA records; return (success, info)."""
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(hostname, "A")
        ips = [r.to_text() for r in answers]
        return True, {"type":"A","ips": ips}
    except Exception:
        try:
            answers = resolver.resolve(hostname, "AAAA")
            ips = [r.to_text() for r in answers]
            return True, {"type":"AAAA","ips": ips}
        except Exception as e2:
            return False, {"error": str(e2)}

# ------------------ Flask App ------------------ #

app = Flask(__name__)

@app.route("/scan", methods=["POST"])
def scan_endpoint():
    payload = request.get_json(force=True)
    domain = payload.get("domain")
    if not domain:
        return jsonify({"error": "domain required"}), 400

    base_domain = domain.strip().lower()
    if base_domain.startswith("http://") or base_domain.startswith("https://"):
        from urllib.parse import urlparse
        base_domain = urlparse(base_domain).hostname or base_domain

    # ---- Recon ---- #
    subs_crt, _ = get_crtsh_subdomains(base_domain)
    subs_s3r, _ = run_sublist3r(base_domain, timeout=60)
    subs_brute = brute_subdomains(base_domain)
    urls_wb, _ = wayback_urls_for_domain(base_domain, limit=1000)

    # Aggregate subdomains and sources, skip emails
    agg = defaultdict(set)
    for s in subs_crt: 
        if "@" not in s:
            agg[s].add("crt.sh")
    for s in subs_s3r: 
        if "@" not in s:
            agg[s].add("sublist3r")
    for s in subs_brute: 
        if "@" not in s:
            agg[s].add("bruteforce")
    import urllib.parse
    for u in urls_wb:
        try:
            host = urllib.parse.urlparse(u).hostname
            if host and host.endswith(base_domain) and "@" not in host:
                agg[host].add("wayback_urls")
        except Exception:
            continue
    agg[base_domain].add("root")

    # Resolve subdomains concurrently
    subdomains_list = list(agg.keys())
    with ThreadPoolExecutor(max_workers=20) as exe:
        futs = {exe.submit(resolve_host_check, s): s for s in subdomains_list}
        subdomains_final = {}
        for fut in as_completed(futs):
            sub = futs[fut]
            subdomains_final[sub] = {
                "sources": sorted(list(agg[sub]))
            }

    # Final simplified result
    results = {
        "domain": base_domain,
        "subdomains": subdomains_final,
        "sources": list(sorted(set(src for srcs in agg.values() for src in srcs)))
    }

    return jsonify(results), 200

# ------------------ Main ------------------ #
if __name__ == "__main__":
    ok, out = pip_install("flask")
    if ok:
        try:
            app.run(host="0.0.0.0", port=5000)
        except Exception as e:
            print("Failed to start Flask server:", e)
    else:
        print("Failed to install Flask. Output:\n", out)
