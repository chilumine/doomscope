# DoomScope - Quick Installation Guide

## ⚡ 5-Minute Setup

### 1. Install Python Packages (2 minutes)
```powershell
cd c:\laragon\www\doomscope
pip install -r requirements.txt
```

### 2. Download ChromeDriver (2 minutes)
1. Check your Chrome version: **Chrome menu → About Google Chrome**
2. Go to: https://chromedriver.chromium.org/downloads
3. Download the matching version
4. Extract to `c:\Program Files\` or add to PATH
5. Verify: `chromedriver --version`

### 3. Install Go Tools (1 minute)
**If Go is NOT installed:**
- Download from: https://go.dev/dl/
- Run installer and follow prompts
- Restart terminal/PowerShell

**Install tools:**
```powershell
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/v2/cmd/httpx@latest
```

Verify:
```powershell
nuclei -version
httpx -version
```

---

## 🚀 Run DoomScope

### Terminal 1: Start Services
```powershell
cd c:\laragon\www\doomscope
python launcher.py
```
- Dashboard available at: **http://127.0.0.1:19000**

### Terminal 2: Run Scan
```powershell
cd c:\laragon\www\doomscope
python doomscope_pipeline.py
```
- Enter domain when prompted (e.g., `example.com`)
- Results saved to: `final_results/<domain>_doomscope_report.json`

---

## 📋 What Gets Installed

| Package | Purpose |
|---------|---------|
| `Flask` | Web server framework |
| `requests` | HTTP client |
| `beautifulsoup4` | HTML parsing |
| `selenium` | Browser automation |
| `httpx` | Advanced HTTP client |
| `dnspython` | DNS queries |
| `Sublist3r` | Subdomain enumeration |
| `arjun` | Parameter discovery |
| `python-Wappalyzer` | Tech detection |
| `colorama` | Terminal colors |

**External Tools:**
- `nuclei` - Vulnerability scanning
- `httpx` v2 - HTTP probing
- `dirsearch` - Directory brute-force (auto-installed)
- `ChromeDriver` - Browser automation
- `wapiti3` (optional) - Web app scanning

---

## ✅ Verify Installation

```powershell
# Check Python packages
pip list | findstr /R "Flask requests beautifulsoup4 selenium"

# Check external tools
nuclei -version
httpx -version
chromedriver --version
dirsearch --help
```

All should display version info without errors.

---

## 🆘 Common Issues & Fixes

### Issue: "chromedriver not found"
**Fix:** Download from chromedriver.chromium.org and add to PATH

### Issue: "nuclei command not found"
**Fix:** Go not installed. Download from go.dev/dl, then run:
```powershell
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

### Issue: "Port 5000 already in use"
**Fix:** Change port in config or kill existing process:
```powershell
netstat -ano | findstr :5000
taskkill /PID <pid> /F
```

### Issue: "ModuleNotFoundError: No module named 'X'"
**Fix:** Reinstall requirements:
```powershell
pip install --upgrade -r requirements.txt
```

---

## 📊 Services & Ports

| Service | Port | Purpose |
|---------|------|---------|
| Subdomain Enum | 5000 | Find subdomains |
| Sensitive Paths | 5001 | Detect sensitive paths |
| Sensitive Login | 5002 | Find login pages |
| Archived Content | 5003 | Wayback Machine scan |
| Secret Parameters | 5004 | Extract parameters |
| Initial FP | 5006 | Initial fingerprint |
| Page Identifier | 5009 | Classify pages |
| Reflected Params | 5122 | Test reflection |
| Tech Fingerprint | 6000 | Detect technologies |
| Public Parameters | 6666 | Public API params |
| JS Analysis | 8005 | Scan JavaScript |
| Directory Search | 8000 | Brute-force directories |
| Basic Security | 8001 | Nuclei scanning |
| API Enumeration | 8002 | Find API endpoints |
| Security Scanner | 9998 | Final scanning |
| **Dashboard** | **19000** | **Service management** |

---

## 📁 Project Structure

```
doomscope/
├── launcher.py                 # Start all services
├── doomscope_pipeline.py       # Run scan pipeline
├── requirements.txt            # Python packages
├── setup.py                    # Automated setup
├── SERVICES_REQUIREMENTS.md    # Detailed requirements
├── REQUIREMENTS_CHECKLIST.md   # Full checklist
├── subdomain_enum/             # Subdomain discovery
├── directory_search/           # Directory brute-force
├── api_enum/                   # API endpoint discovery
├── js_analysis/                # JavaScript analysis
├── basic_security_scan/        # Nuclei scanning
├── tech_fingerprinting/        # Technology detection
├── secret_parameters/          # Parameter extraction
├── reflected_parameter_check/  # XSS testing
├── security_scanner/           # Final security scan
├── sensitive_path_enum/        # Sensitive path detection
├── sensitive_login_enum/       # Login page detection
├── archived_contents/          # Wayback Machine scan
├── page_identifier/            # Page classification
├── initial_fingerprinting/     # Initial fingerprinting
└── final_results/              # Scan reports (generated)
```

---

## 🎯 Next Steps

1. Run `python launcher.py` and check dashboard: http://127.0.0.1:19000
2. Run `python doomscope_pipeline.py` with a test domain
3. Check results in `final_results/` folder
4. Review detailed docs in `SERVICES_REQUIREMENTS.md`

---

## 📚 Full Documentation

- `SERVICES_REQUIREMENTS.md` - Detailed service info
- `REQUIREMENTS_CHECKLIST.md` - Complete checklist
- Service config files - Individual service settings

---

**Ready to scan? Good luck!** 🔍
