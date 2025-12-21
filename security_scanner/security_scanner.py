from flask import Flask, request, jsonify
import subprocess
import json
import re
import os

app = Flask(__name__)

# ================= PATH FIX ================= #

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REFLECTION_DIR = os.path.abspath(
    os.path.join(BASE_DIR, "..", "reflected_parameter_check")
)

# ================= WAPITI ================= #

def run_wapiti(url, parameter):
    cmd = (
        f'wapiti -u "{url}" '
        '--flush-session --flush-attacks '
        '--store-session C:\\Temp\\wapiti_%RANDOM% '
        '--store-config C:\\Temp\\wapiti_cfg_%RANDOM% '
        f'-r {parameter}'
    )

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    process = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    return [line.rstrip() for line in process.stdout]


def parse_wapiti_output(lines):
    results = []
    current_module = None
    waiting_for_dash = False

    for line in lines:
        m = re.search(r"\[\*\] Launching module (\w+)", line)
        if m:
            current_module = m.group(1)
            waiting_for_dash = False
            continue

        if line.strip() == "---" and current_module:
            waiting_for_dash = True
            continue

        if waiting_for_dash:
            finding = line.strip()

            if (
                not finding or
                "HTTP 500" in finding or
                "Received a HTTP" in finding
            ):
                waiting_for_dash = False
                continue

            results.append({
                "vulnerability": current_module,
                "finding": finding
            })
            waiting_for_dash = False

    return results


# ================= LOAD REFLECTED ================= #

def load_reflected_targets(domain):
    domain_key = domain.replace(".", "_")

    files = [
        f"public_{domain_key}_selenium_reflection.txt",
        f"archived_{domain_key}_selenium_reflection.json",
        f"{domain_key}_selenium_reflection.json"
    ]

    targets = []

    for fname in files:
        path = os.path.join(REFLECTION_DIR, fname)

        if not os.path.exists(path):
            continue

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # ✅ data is LIST of objects (زي اللي باعتها)
            for item in data:
                if item.get("reflected") is True:
                    targets.append({
                        "url": item["url"],
                        "parameter": item["parameter"]
                    })

        except Exception as e:
            print(f"[!] Failed reading {fname}: {e}")

    return targets


# ================= API ================= #

@app.route("/scan", methods=["POST"])
def scan_domain():
    body = request.get_json()

    if not body or "domain" not in body:
        return jsonify({"error": "domain is required"}), 400

    domain = body["domain"]
    targets = load_reflected_targets(domain)

    if not targets:
        return jsonify({
            "domain": domain,
            "message": "No reflected=true parameters found"
        })

    findings = []

    for t in targets:
        raw = run_wapiti(t["url"], t["parameter"])
        parsed = parse_wapiti_output(raw)

        if parsed:
            findings.append({
                "url": t["url"],
                "parameter": t["parameter"],
                "results": parsed
            })

    return jsonify({
        "domain": domain,
        "total_reflected": len(targets),
        "vulnerable": len(findings),
        "data": findings
    })


# ================= RUN ================= #

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9998, debug=False)
