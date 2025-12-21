from flask import Flask, request, jsonify
import subprocess
import shlex
import shutil
import sys
import os
import platform

app = Flask(__name__)

# ======================================================
# التأكد من وجود Go و httpx v2، وتنصيبهما تلقائياً
# ======================================================
def ensure_go():
    if shutil.which("go") is None:
        print("Go is not installed. Please install Go first: https://go.dev/dl/")
        sys.exit(1)
    else:
        print("Go found.")

def ensure_httpx():
    # التحقق من نسخة httpx
    httpx_path = shutil.which("httpx")
    if httpx_path:
        try:
            # تحقق من النسخة للتأكد أنها v2
            version_check = subprocess.run(["httpx", "-version"], capture_output=True, text=True)
            if "v2" in version_check.stdout:
                print("httpx v2 is already installed.")
                return
            else:
                print("httpx found but not v2, reinstalling...")
        except Exception:
            print("Failed to check httpx version, reinstalling...")

    print("Installing httpx v2...")
    try:
        subprocess.run(shlex.split("go install github.com/projectdiscovery/httpx/v2/cmd/httpx@latest"), check=True)
        # تحديث PATH تلقائي
        go_bin = os.path.expanduser("~/go/bin")
        if platform.system() == "Windows":
            go_bin = os.path.join(os.environ["USERPROFILE"], "go", "bin")
        if go_bin not in os.environ["PATH"]:
            os.environ["PATH"] += os.pathsep + go_bin
        print("httpx v2 installed successfully.")
    except subprocess.CalledProcessError as e:
        print("Failed to install httpx:", e)
        sys.exit(1)

# ======================================================
# تأكيد وجود Go و httpx
# ======================================================
ensure_go()
ensure_httpx()

# ======================================================
# Flask API
# ======================================================
@app.route("/scan", methods=["POST"])
def scan_urls():
    data = request.get_json()
    urls = data.get("urls", [])
    results = []

    if not urls:
        return jsonify({"error": "No URLs provided"}), 400

    for url in urls:
        try:
            cmd = f"httpx -silent -title -status-code -tech-detect -follow-redirects -u {url}"
            process = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=20)
            output = process.stdout.strip()

            result = {"url": url, "status": None, "title": None, "page_type": None}
            if output:
                # Status code
                if "[" in output and "]" in output:
                    status_part = output.split("[")[1].split("]")[0]
                    result["status"] = int(status_part)
                # Title
                if 'title="' in output:
                    result["title"] = output.split('title="')[1].split('"')[0]
                # Page type / tech
                if 'tech=[' in output:
                    tech = output.split('tech=[')[1].split(']')[0].replace('"','').split(",")
                    tech = [t.strip() for t in tech if t.strip()]
                    result["page_type"] = tech

            # ✅ فقط لو httpx عرف النوع
            if result["page_type"]:
                results.append(result)

        except subprocess.TimeoutExpired:
            continue
        except Exception:
            continue

    return jsonify(results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5006)
