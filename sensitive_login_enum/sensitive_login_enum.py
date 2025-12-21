from flask import Flask, request, jsonify
import os
import re
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

# ===========================
# LOGIN DETECTOR FUNCTION
# ===========================
def is_login_page(url, html_text):
    score = 0
    html_lower = html_text.lower()
    soup = BeautifulSoup(html_text, "html.parser")

    # RULE 1 – URL contains login keywords
    url_keywords = ["login", "signin", "auth", "account/login", "user/login", "admin/login", "session"]
    if any(k in url.lower() for k in url_keywords):
        score += 4

    # RULE 2 – Has password input
    forms = soup.find_all("form")
    for form in forms:
        if form.find("input", {"type": "password"}):
            score += 5
            break

    # RULE 3 – Has username/email input
    user_inputs = ["username", "email", "user", "login", "identifier"]
    for input_tag in soup.find_all("input"):
        field_name = input_tag.get("name", "").lower()
        field_id = input_tag.get("id", "").lower()
        field_type = input_tag.get("type", "").lower()

        if any(u in field_name for u in user_inputs) or \
           any(u in field_id for u in user_inputs) or \
           field_type in ["email"]:
            score += 2
            break

    # RULE 4 – Login keywords in text
    login_keywords = ["login", "sign in", "log in", "auth", "authentication", "member login", "secure login"]
    if any(k in html_lower for k in login_keywords):
        score += 3

    # RULE 5 – Login button
    buttons = soup.find_all(["button", "input"])
    for b in buttons:
        txt = b.get_text(strip=True).lower() if b.name == "button" else b.get("value", "").lower()
        if any(x in txt for x in ["login", "log in", "sign in"]):
            score += 4
            break

    # RULE 6 – Forgot/Reset password links
    fp_keywords = ["forgot password", "reset password", "lost password", "recover account"]
    if any(k in html_lower for k in fp_keywords):
        score += 4

    # RULE 7 – form action looks like login
    for form in forms:
        action = form.get("action", "").lower()
        if any(x in action for x in ["login", "auth", "signin", "session"]):
            score += 3
            break

    # RULE 8 – Username + password combination
    inputs = soup.find_all("input")
    has_user = any("user" in i.get("name", "").lower() or "email" in i.get("name", "").lower() for i in inputs)
    has_pass = any(i.get("type", "").lower() == "password" for i in inputs)

    if has_user and has_pass:
        score += 6

    # RULE 9 – Title says login
    title_tag = soup.title.string.lower() if soup.title and soup.title.string else ""
    if any(k in title_tag for k in ["login", "signin", "sign in", "authenticate"]):
        score += 2

    # RULE 10 – Regex patterns
    if re.search(r"(enter your|please enter|access your)\s+(account|credentials)", html_lower):
        score += 3

    return score >= 7


# ===========================
# READ URLS FROM DIRECTORY SEARCH
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

    login_pages = []

    for url in all_urls:
        try:
            r = requests.get(url, timeout=10)
            text = r.text

            if is_login_page(url, text):
                login_pages.append(url)

        except Exception as e:
            pass

    return {
        "domain": domain,
        "total_urls_checked": len(all_urls),
        "login_pages_found": len(login_pages),
        "login_pages": login_pages
    }


# ===========================
# FLASK API
# ===========================
@app.route("/scan", methods=["POST"])
def scan_login():
    data = request.json
    if not data or "domain" not in data:
        return jsonify({"error": "Missing 'domain' in JSON"}), 400

    domain = data["domain"]
    result = process_domain(domain)
    return jsonify(result)


# ===========================
# RUN SERVER
# ===========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)
