from flask import Flask, request, jsonify
import requests
import re

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
    "internal_node_modules": r"/srv/node_modules/@internal/[A-Za-z0-9_\-\/]+",

    # -------------------- Emails --------------------
    "emails": r"\b[a-zA-Z0-9._%+-]{1,64}@(inisev\.com|gmail\.com|yahoo\.com|outlook\.com)\b",

    # -------------------- JWT Tokens --------------------
    "jwt_tokens": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
}

# ==========================================================
# HELPERS
# ==========================================================
def fetch_wayback_lines(domain):
    url = (
        "http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
    )
    r = requests.get(url)
    return list(set(r.text.splitlines()))

def extract_patterns(text):
    findings = {}
    for name, pattern in REGEX_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            findings[name] = list(set(matches))
    return findings

def save_results(domain, results):
    filename = f"sensitive_tokens_archieved_{domain.replace('.', '_')}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        for line, data in results.items():
            f.write(f"Line: {line}\n")
            for key, values in data.items():
                f.write(f"  {key}:\n")
                for v in values:
                    f.write(f"    {v}\n")
            f.write("\n")
    return filename

# ==========================================================
# API
# ==========================================================
@app.route("/scan", methods=["POST"])
def scan_domain():
    data = request.json
    domain = data.get("domain")
    if not domain:
        return jsonify({"error": "domain is required"}), 400

    lines = fetch_wayback_lines(domain)
    results = {}

    for line in lines:
        findings = extract_patterns(line)
        if findings:
            results[line] = findings

    saved_file = save_results(domain, results)

    return jsonify({
        "domain": domain,
        "total_lines": len(lines),
        "hits": results,
        "saved_file": saved_file
    })

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=9555)
