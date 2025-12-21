from flask import Flask, request, jsonify
import os
import re
import json
import requests

app = Flask(__name__)

# ===========================
# CONFIG
# ===========================
STATIC_THRESHOLD = 10  # لو فيه 10 صفحات أو أكتر بنفس الحجم، تعتبر ستاتيك

# ===========================
# LOAD SENSITIVE PATTERNS
# ===========================
def load_sensitive_patterns(filename="patterns.json"):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return []

sensitive_patterns = load_sensitive_patterns()

# ===========================
# KEYWORDS
# ===========================
keywords = [
    "password","passwd","pwd","username","user","login","signin","credential","creds",
    "auth","authentication","email","gmail","hotmail","yahoo","outlook","admin","root",
    "superadmin","account","profile","passphrase",
    "paypal","stripe","bank","iban","swift","visa","mastercard","credit card","cvv",
    "exp date","transaction","payment","checkout","gateway","billing",
    "Index of /","Parent Directory","Directory Listing","Apache Directory Listing",
    "nginx autoindex","listings","Index.html","Index of",
    "hacked by","hacked","defaced","pwned","owned","0x","mr hacker",
    "your site has been hacked","security breach",
    "contact us","contact form","support email","phone number","address",
    "contact information","reach us",
    "aws_access_key_id","aws_secret_access_key","aws_session_token","google_api_key",
    "firebase","azure_key","s3 bucket","cloudfront","gcp","azure","cloudflare",
    "digitalocean",
    "debug","stack trace","traceback","warning","fatal error","exception",
    "debug mode","test mode","development config","env=",".env","dotenv","logs",
    "error log",
    "mysql","mariadb","sql","postgres","mongodb","redis","db_user","db_pass",
    "database error","connection failed","pdo","jdbc","sql injection","db hostname",
    ".htaccess","backup","bak",".git",".svn","config.php","wp-config","config.json",
    "settings.py","credentials",
    "server version","apache","nginx","php version","laravel","django","express",
    "spring","iis","ubuntu","windows server",
    "exposed","leaked","publicly accessible","sensitive","forbidden","unauthorized",
    "403","401","500","stack",
    "@gmail.com","@yahoo.com","@hotmail.com","@outlook.com","firstname","lastname",
    "full name","phone","mobile","dob","national id","address","user_id",
    "token","secret","key=","api key","private key","jwt","session id","cookie",
    "csrf","xsrf","bearer",
    "/var/www","/home/","/root/","/etc/","C:\\Windows","C:\\Users","application logs",
    "phpinfo()","phpmyadmin",
    "admin panel","dashboard","cms","cpanel","whm","management panel","superuser",
    "panel login",
]

# ===========================
# RESPONSE FUNCTIONS
# ===========================
def detect_response_type(url):
    try:
        response = requests.get(url, timeout=10)
        content_type = response.headers.get('Content-Type', '').lower()

        if 'application/json' in content_type:
            detected_type = 'json'
        elif 'text/html' in content_type:
            detected_type = 'html'
        elif 'text/plain' in content_type:
            detected_type = 'text'
        elif 'application/xml' in content_type or 'text/xml' in content_type:
            detected_type = 'xml'
        elif 'application/pdf' in content_type:
            detected_type = 'pdf'
        elif content_type.startswith('image/'):
            detected_type = 'image'
        elif content_type.startswith('audio/'):
            detected_type = 'audio'
        elif content_type.startswith('video/'):
            detected_type = 'video'
        elif 'application/zip' in content_type:
            detected_type = 'zip'
        elif 'application/octet-stream' in content_type:
            detected_type = 'binary'
        else:
            detected_type = 'unknown'

        if detected_type == 'unknown':
            text = response.text.strip()
            if text.startswith('{') or text.startswith('['):
                detected_type = 'json'
            elif text.startswith('<'):
                detected_type = 'xml/html'
            elif len(text) < 2000:
                detected_type = 'text'
            else:
                detected_type = 'binary'

        return {
            'url': url,
            'detected_type': detected_type,
            'content_type_header': content_type,
            'text': response.text,
            'page_size_bytes': len(response.content)
        }
    except Exception as e:
        return {'url': url, 'error': True, 'message': str(e)}

def detect_allowed_methods(url):
    try:
        response = requests.options(url, timeout=10)
        allowed = response.headers.get('Allow')
        methods = [m.strip() for m in allowed.split(',')] if allowed else []
        return {'url': url, 'allowed_methods': methods}
    except Exception as e:
        return {'url': url, 'error': True, 'message': str(e)}

# ===========================
# SENSITIVE LEAKS DETECTOR
# ===========================
def detect_sensitive_leaks(text):
    findings = []
    seen = set()
    for pattern in sensitive_patterns:
        matches = re.finditer(pattern["regex"], text, re.IGNORECASE | re.DOTALL)
        for match in matches:
            mtxt = match.group(0).strip()
            key = f"{pattern['name']}::{mtxt}"
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "name": pattern["name"],
                "severity": pattern["severity"],
                "description": pattern["description"],
                "matched_text": mtxt[:500]
            })
    return findings

def keyword_scan(text):
    found = []
    for kw in keywords:
        if re.search(re.escape(kw), text, re.IGNORECASE):
            found.append(kw)
    return list(set(found))

# ===========================
# RISK CALCULATION
# ===========================
def calculate_risk_score(report, page_size_counts):
    # robots.txt و sitemap.xml صفر ريسك
    if "robots.txt" in report["url"].lower() or "sitemap.xml" in report["url"].lower():
        return 0
    score = 0
    if report.get('keywords_found_count', 0) > 0:
        score += 1
    if report.get('findings_count', 0) > 0:
        score += 1
    if report.get('detected_type') != 'html':
        score += 1
    if report.get("is_static", False):
        score = max(0, score - 1)
    return score

# ===========================
# FULL CHECK
# ===========================
def full_url_security_check(url):
    # robots.txt و sitemap.xml صفر ريسك وما نبحثش عن حساسيات او كلمات مفتاحية
    if "robots.txt" in url.lower() or "sitemap.xml" in url.lower():
        response_info = detect_response_type(url)
        methods_info = detect_allowed_methods(url)
        return {
            "url": url,
            "detected_type": response_info.get("detected_type", "text"),
            "content_type_header": response_info.get("content_type_header", ""),
            "page_size_bytes": response_info.get("page_size_bytes", 0),
            "allowed_methods": methods_info.get("allowed_methods", []),
            "sensitive_leaks": [],
            "findings_count": 0,
            "highest_severity_finding": None,
            "has_sensitive_leaks": False,
            "keywords_found_count": 0,
            "keywords_found": [],
        }

    response_info = detect_response_type(url)
    if response_info.get("error"):
        return response_info
    methods_info = detect_allowed_methods(url)
    leaks_info = detect_sensitive_leaks(response_info["text"])
    keywords_found = keyword_scan(response_info["text"])
    highest_severity = max(leaks_info, key=lambda x: x['severity']) if leaks_info else None
    return {
        "url": url,
        "detected_type": response_info["detected_type"],
        "content_type_header": response_info["content_type_header"],
        "page_size_bytes": response_info["page_size_bytes"],
        "allowed_methods": methods_info.get("allowed_methods", []),
        "sensitive_leaks": leaks_info,
        "findings_count": len(leaks_info),
        "highest_severity_finding": highest_severity,
        "has_sensitive_leaks": len(leaks_info) > 0,
        "keywords_found_count": len(keywords_found),
        "keywords_found": keywords_found
    }

# ===========================
# EXTRACT URLs
# ===========================
def extract_urls_from_file(filepath):
    urls = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                match = re.match(r"(\d{3})\s+[^\s]+\s+(https?://[^\s]+)", line)
                if match:
                    status = int(match.group(1))
                    url = match.group(2)
                    if status in (200, 500):
                        urls.append(url)
    except:
        pass
    return urls

# ===========================
# PROCESS DOMAIN
# ===========================
def process_domain(domain):
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
    BASE_RESULTS_DIR = os.path.join(PROJECT_ROOT, "directory_search", "results")

    folder_name = domain.replace(".", "_")
    folder_path = os.path.join(BASE_RESULTS_DIR, folder_name)

    if not os.path.isdir(folder_path):
        return {"error": True, "message": f"Folder not found: {folder_path}"}

    all_urls = []
    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):
            filepath = os.path.join(folder_path, filename)
            all_urls.extend(extract_urls_from_file(filepath))

    all_urls = list(set(all_urls))
    page_size_counts = {}
    temp_reports = []

    for url in all_urls:
        report = full_url_security_check(url)
        temp_reports.append(report)
        size = report.get("page_size_bytes", 0)
        page_size_counts[size] = page_size_counts.get(size, 0) + 1

    results = []
    for report in temp_reports:
        page_size = report.get("page_size_bytes", 0)
        # اعتبار الصفحة ستاتيك لو عدد الصفحات بنفس الحجم >= STATIC_THRESHOLD
        report["is_static"] = page_size_counts.get(page_size, 0) >= STATIC_THRESHOLD
        report["risk_score"] = calculate_risk_score(report, page_size_counts)
        results.append({"url": report["url"], "report": report})

    return {
        "domain": domain,
        "total_urls": len(all_urls),
        "results": results
    }

# ===========================
# FLASK API ENDPOINT
# ===========================
@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    if not data or "domain" not in data:
        return jsonify({"error": "Missing 'domain' in JSON"}), 400
    domain = data["domain"]
    output = process_domain(domain)
    return jsonify(output)

# ===========================
# RUN SERVER
# ===========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
