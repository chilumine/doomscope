from flask import Flask, request, jsonify
import os
import re
import json
import requests

app = Flask(__name__)

# ==========================================================
# REGEX PATTERNS
# ==========================================================
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



# ==========================================================
# HELPERS
# ==========================================================

def js_only(url):
    return url.lower().endswith(".js") or ".js?" in url.lower()


def fetch_js(url):
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return None


# ==========================================================
# MAIN SCAN LOGIC
# ==========================================================
def scan_domain(domain):

    base_path = os.path.join(
        os.getcwd(),
        "../api_enum",
        "api_results",
        domain,
        "aggregate.json"
    )

    if not os.path.isfile(base_path):
        return {"error": f"aggregate.json not found for domain: {domain}"}

    # ---------------------------------------
    # Load JSON
    # ---------------------------------------
    with open(base_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    js_urls = set()

    # ---------------------------------------
    # Extract JS URLs from endpoints
    # ---------------------------------------
    for item in data.get("results", []):
        for api in item.get("api_endpoints", []):
            url = api.get("endpoint", "")
            if url and js_only(url):
                js_urls.add(url)

    findings = []

    # ---------------------------------------
    # Fetch & scan JS files
    # ---------------------------------------
    for js_url in js_urls:
        content = fetch_js(js_url)
        if not content:
            continue

        for leak_type, pattern in REGEX_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                findings.append({
                    "file_url": js_url,
                    "leak_type": leak_type,
                    "matches": list(set(matches))
                })

    return {
        "domain": domain,
        "js_files_count": len(js_urls),
        "findings": findings
    }


# ==========================================================
# API ROUTE
# ==========================================================
@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    if not data or "domain" not in data:
        return jsonify({"error": "Missing 'domain'"}), 400
    return jsonify(scan_domain(data["domain"]))


# ==========================================================
# RUN SERVER
# ==========================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7006, debug=True)
