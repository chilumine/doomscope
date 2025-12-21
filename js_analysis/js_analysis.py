#!/usr/bin/env python3
import os
import re
import json
from pathlib import Path
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from flask import Flask, request, jsonify
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# ------------------------------
# Config
# ------------------------------
MAX_WORKERS = 5
SCAN_SERVICE = "http://127.0.0.1:5000/scan"
RESULTS_DIR = Path("./results_js")  # نفس فولدر JS analysis
RESULTS_DIR.mkdir(exist_ok=True)

# ------------------------------
# Selenium Headless Options
# ------------------------------
def silent_chrome_options():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--log-level=3")
    options.add_experimental_option("excludeSwitches", ["enable-logging"])
    return options

# ------------------------------
# Regex patterns for JS secrets
# ------------------------------
REGEX_PATTERNS = {
    # -------------------- AWS --------------------
    "aws_access_key_id": r"AKIA[0-9A-Z]{16}",
    "aws_secret_access_key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]",
    "aws_arn": r"arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9_+=,.@\-_/]+",
    "s3_bucket": r"s3:\/\/[a-z0-9\-\.]{3,63}",
    "aws_rds": r"[a-z0-9-]+\.rds\.amazonaws\.com",

    # -------------------- Google / Firebase --------------------
    "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
    "firebase_api_key": r"firebaseConfig\s*=\s*{[^}]*apiKey\s*:\s*['\"][^'\"]+['\"]",
    "firebase_url": r"https:\/\/[a-z0-9-]+\.firebaseio\.com",

    # -------------------- GitHub / GitLab --------------------
    "github_token": r"ghp_[0-9a-zA-Z]{36}",
    "github_pat": r"ghp_[a-zA-Z0-9]{36}",
    "gitlab_token": r"glpat-[0-9a-zA-Z-_]{20}",
    "gitlab_runner": r"glrt-[a-zA-Z0-9_-]{20}",

    # -------------------- Payment Keys --------------------
    "stripe_secret_key": r"sk_live_[0-9a-zA-Z]{24}",
    "stripe_public_key": r"pk_live_[0-9a-zA-Z]{24}",

    # -------------------- Cloud / SaaS --------------------
    "twilio_api_key": r"SK[0-9a-fA-F]{32}",
    "sendgrid_api_key": r"SG\.[\w\d\-_]{22}\.[\w\d\-_]{43}",
    "mailgun_api_key": r"key-[0-9a-zA-Z]{32}",
    "digitalocean_token": r"dop_v1_[a-z0-9]{64}",
    "shopify_access_token": r"shpat_[0-9a-fA-F]{32}",

    # -------------------- Messaging / Bots --------------------
    "telegram_bot_token": r"\d{9}:[a-zA-Z0-9_-]{35}",
    "discord_bot_token": r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
    "discord_webhook": r"https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+",

    # -------------------- OAuth / Secrets --------------------
    "oauth_client_secret": r"(?i)client_secret['\"\s:=]+[a-zA-Z0-9\-_.~]{20,}",
    "oauth_client_id": r"(?i)client_id['\"\s:=]+[a-zA-Z0-9\-_.~]{10,}",

    # -------------------- Database URLs --------------------
    "mongodb_url": r"mongodb(\+srv)?:\/\/[^\s'\"]+",
    "postgres_url": r"postgres(?:ql)?:\/\/[^\s'\"]+",
    "mysql_url": r"mysql:\/\/[^\s'\"]+",
    "redis_url": r"redis:\/\/[^\s'\"]+",

    # -------------------- Sentry / Cloudinary --------------------
    "sentry_dsn": r"https:\/\/[a-zA-Z0-9]+@[a-z]+\.ingest\.sentry\.io\/\d+",
    "cloudinary_url": r"cloudinary:\/\/[0-9]{15}:[a-zA-Z0-9]+@[a-zA-Z]+",

    # -------------------- Tokens / API Keys --------------------
    "plaid_client_secret": r"plaid(.{0,20})?(client)?secret['\"\s:=]+[a-z0-9-_]{30,}",
    "steam_api_key": r"(?i)steam(.{0,20})?key['\"\s:=]+[a-zA-Z0-9]{32}",

    # -------------------- Webhooks --------------------
    "teams_webhook": r"https:\/\/[a-z]+\.webhook\.office\.com\/webhookb2\/[a-zA-Z0-9@\-]+\/.*",

    # -------------------- Private Keys --------------------
    "private_key_block": r"-----BEGIN (RSA|DSA|EC|OPENSSH)? PRIVATE KEY-----",
    "pem_block": r"-----BEGIN CERTIFICATE-----",
    "pgp_private_block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",

    # -------------------- Internal Paths --------------------
"internal_unix_home": r"/home/(dev|developer|admin|root|test|ci|staging)/[A-Za-z0-9_\-]+",
"internal_repo_path": r"/(srv|opt|var)/(git|repos|internal|ci)/[A-Za-z0-9_\-\/]+",
"internal_ci_artifacts": r"/var/lib/(jenkins|gitlab-runner)/[A-Za-z0-9_\-\/]+",
"internal_build_path": r"/builds/[A-Za-z0-9_\-\/]+",
"internal_backup_path": r"/var/backups/[A-Za-z0-9_\-\/]+",
"internal_k8s_config": r"/etc/(kubernetes|k8s)/[A-Za-z0-9_\-\/]+",
"internal_docker_path": r"/var/lib/docker/[A-Za-z0-9_\-\/]+",
"internal_nginx_sites": r"/etc/nginx/sites-(available|enabled)/[A-Za-z0-9_\-\.]+",
"internal_apache_conf": r"/etc/apache2/(sites|conf)-[A-Za-z0-9_\-\/]+",
"internal_logs": r"/var/log/(dev|internal|private|secure)/[A-Za-z0-9_\-\.]+",
"internal_config_file": r"/etc/(internal|private|secrets)/[A-Za-z0-9_\-\.]+",
"internal_macos_path": r"/Users/(dev|developer|admin)/[A-Za-z0-9_\-\/]+",
"internal_tmp_sensitive": r"/tmp/(internal|private|secrets|debug)_[A-Za-z0-9_\-\.]+",
"internal_python_venv": r"/(srv|opt)/venv/[A-Za-z0-9_\-\/]+",
"internal_node_modules": r"/srv/node_modules/@internal/[A-Za-z0-9_\-\/]+"

}



# ------------------------------
# Helpers
# ------------------------------
def same_domain_only(parent_url, src):
    parent = urlparse(parent_url)
    if src.startswith("//"):
        src = "https:" + src
    if src.startswith("/"):
        src = urljoin(parent_url, src)
    parsed = urlparse(src)
    if not parsed.netloc:
        return None
    if parsed.netloc.endswith(parent.netloc):
        return src
    return None

def get_js_urls(url):
    options = silent_chrome_options()
    driver = webdriver.Chrome(options=options)
    driver.get(url)
    soup = BeautifulSoup(driver.page_source, "html.parser")
    driver.quit()

    js_urls = []
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            filtered = same_domain_only(url, src)
            if filtered:
                js_urls.append(filtered)
    return list(set(js_urls))

def download_js(js_url):
    try:
        resp = requests.get(js_url, timeout=10)
        if resp.status_code == 200:
            return resp.text
    except:
        return None
    return None

def scan_js_for_secrets(js_content):
    findings = {}
    for name, pattern in REGEX_PATTERNS.items():
        matches = re.findall(pattern, js_content)
        if matches:
            findings[name] = list(set(matches))  # remove duplicates
    return findings

def fetch_subdomains_from_scan_service(domain):
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
    return sorted(set([s.strip() for s in subs if s and "." in s]))

# ------------------------------
# JS Scan for one host
# ------------------------------
def run_js_scan(host):
    host_url = host if host.startswith("http") else f"https://{host}"
    js_urls = get_js_urls(host_url)
    host_findings = {}
    for js in js_urls:
        content = download_js(js)
        if content:
            results = scan_js_for_secrets(content)
            if results:
                host_findings[js] = results
    return {"host": host, "findings": host_findings}

# ------------------------------
# Flask app
# ------------------------------
app = Flask(__name__)

@app.route("/run", methods=["POST"])
def run():
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

    # اسم الملف حسب الدومين الأصلي
    domain_name = label
    out_file = RESULTS_DIR / f"{domain_name}_results.txt"

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(run_js_scan, host): host for host in subdomains}
        for f in as_completed(futures):
            try:
                res = f.result()
            except Exception as e:
                res = {"host": futures[f], "error": str(e)}
            results.append(res)

    # حفظ النتائج في نفس فولدر JS analysis
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return jsonify({"domain": domain_name, "total_targets": len(subdomains), "results_file": str(out_file), "results": results})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8005, debug=True)
