import subprocess
import signal
import os
from flask import Flask, render_template, redirect, url_for

# root folder of doomscope
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, template_folder="dashboard/templates")

# ===============================
# SERVICE REGISTRY (relative paths)
# ===============================
SERVICES = {
    "subdomain_enum": {"folder": "subdomain_enum", "file": "subdomain_enum.py", "port": 5000},
    "tech_fingerprinting": {"folder": "tech_fingerprinting", "file": "tech_fingerprinting.py", "port": 6000},
    "sensitive_path_enum": {"folder": "sensitive_path_enum", "file": "sensitive_path_enum.py", "port": 5001},
    "sensitive_login_enum": {"folder": "sensitive_login_enum", "file": "sensitive_login_enum.py", "port": 5002},
    "archived_contents": {"folder": "archived_contents", "file": "archived_contents.py", "port": 5003},
    "secret_parameters": {"folder": "secret_parameters", "file": "secret_parameters.py", "port": 5004},
    "initial_fingerprinting": {"folder": "initial_fingerprinting", "file": "initial_fingerprinting.py", "port": 5006},
    "page_identifier": {"folder": "page_identifier", "file": "page_identifier.py", "port": 5009},
    "public_page_identifier": {"folder": "page_identifier", "file": "public_page_identifier.py", "port": 5109},
    "reflected_parameter_check": {"folder": "reflected_parameter_check", "file": "reflected_parameter_check.py", "port": 5122},
    "archived_reflected_parameter_check": {"folder": "reflected_parameter_check", "file": "archived_reflected_parameter_check.py", "port": 5222},
    "public_parameters": {"folder": "api_enum", "file": "public_parameters.py", "port": 6666},
    "public_reflected_parameter_check": {"folder": "reflected_parameter_check", "file": "public_reflected_parameter_check.py", "port": 6667},
    "archived_js_analysis": {"folder": "js_analysis", "file": "archived_js_analysis.py", "port": 7072},
    "hidden_js_analysis": {"folder": "js_analysis", "file": "hidden_js_analysis.py", "port": 7002},
    "public_js_analysis": {"folder": "js_analysis", "file": "public_js_analysis.py", "port": 7006},
    "js_analysis": {"folder": "js_analysis", "file": "js_analysis.py", "port": 8005},
    "directory_search": {"folder": "directory_search", "file": "directory_search.py", "port": 8000},
    "basic_security_scan": {"folder": "basic_security_scan", "file": "basic_security_scan.py", "port": 8001},
    "api_enum": {"folder": "api_enum", "file": "api_enum.py", "port": 8002},
    "js_archived": {"folder": "archived_contents", "file": "js_archived.py", "port": 9557},
    "archived_parameters": {"folder": "archived_contents", "file": "archived_parameters.py", "port": 9565},
    "sensitive_token_archivied": {"folder": "archived_contents", "file": "sensitive_token_archivied.py", "port": 9555},
    "security_scanner": {"folder": "security_scanner", "file": "security_scanner.py", "port": 9998},
}

processes = {}

# ===============================
# PROCESS CONTROL
# ===============================
def start_service(name):
    if name in processes and processes[name].poll() is None:
        return

    svc = SERVICES[name]
    entry_path = os.path.join(BASE_DIR, svc["folder"], svc["file"])
    proc = subprocess.Popen(
        ["python", entry_path],
        cwd=os.path.join(BASE_DIR, svc["folder"]),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW
    )
    processes[name] = proc

def stop_service(name):
    proc = processes.get(name)
    if proc and proc.poll() is None:
        proc.terminate()

def service_status(name):
    proc = processes.get(name)
    if not proc:
        return "stopped"
    if proc.poll() is None:
        return "running"
    return "crashed"

# ===============================
# DASHBOARD
# ===============================
@app.route("/")
def index():
    data = []
    for name, meta in SERVICES.items():
        proc = processes.get(name)
        data.append({
            "name": name,
            "port": meta["port"],
            "status": service_status(name),
            "pid": proc.pid if proc and proc.poll() is None else "-"
        })
    return render_template("index.html", services=data)

@app.route("/start/<name>")
def start(name):
    start_service(name)
    return redirect(url_for("index"))

@app.route("/stop/<name>")
def stop(name):
    stop_service(name)
    return redirect(url_for("index"))

@app.route("/restart/<name>")
def restart(name):
    stop_service(name)
    start_service(name)
    return redirect(url_for("index"))

# ===============================
# MAIN
# ===============================
if __name__ == "__main__":
    # تشغيل كل السيرفيسات تلقائي
    for svc in SERVICES:
        start_service(svc)

    app.run(host="0.0.0.0", port=19000, debug=False)
