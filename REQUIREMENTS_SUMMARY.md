# 🛡️ DoomScope - Complete Requirements Summary

## 📦 Python Packages (requirements.txt)

```txt
Flask>=2.0                      # Web framework
requests>=2.25                  # HTTP client
urllib3>=1.26                   # HTTP utilities
beautifulsoup4>=4.9             # HTML parsing
lxml>=4.6                       # XML/HTML processing
selenium>=4.0                   # Browser automation
httpx>=0.24.0                   # Advanced HTTP
Sublist3r                       # Subdomain enumeration
waybackpy>=3.2                  # Wayback Machine API
dnspython>=2.0                  # DNS lookups
tldextract>=3.0                 # Domain extraction
arjun                           # Parameter discovery
python-Wappalyzer>=6.0          # Tech fingerprinting
colorama>=0.4                   # Terminal colors
psycopg>=3.0                    # PostgreSQL (optional)
```

---

## 🔧 External Tools (Non-Python)

### Required
1. **Go 1.17+** (https://go.dev/dl/)
   ```bash
   go version
   ```

2. **ChromeDriver** (https://chromedriver.chromium.org/)
   - Must match your Chrome version
   - Add to PATH or specify location in code

### Install via Go
```bash
# Nuclei - Vulnerability Scanner
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# httpx - HTTP Probe Tool  
go install github.com/projectdiscovery/httpx/v2/cmd/httpx@latest
```

### Install via Git
```bash
# dirsearch - Directory Brute-Force
git clone https://github.com/maurosoria/dirsearch.git
# OR (auto-cloned if missing)
pip install dirsearch
```

### Install via pip
```bash
# wapiti3 - Web App Security Scanner
pip install wapiti3

# xnlinkfinder - API Endpoint Extractor
pip install xnlinkfinder
```

---

## 📊 Service Requirements Matrix

| Service | Port | Python Packages | External Tools | Browser |
|---------|------|-----------------|-----------------|---------|
| subdomain_enum | 5000 | requests, Flask, dnspython, waybackpy, Sublist3r | - | ❌ |
| sensitive_path_enum | 5001 | requests, Flask | - | ❌ |
| sensitive_login_enum | 5002 | requests, Flask, beautifulsoup4 | - | ❌ |
| archived_contents | 5003 | requests, Flask | - | ❌ |
| secret_parameters | 5004 | Flask, requests, arjun | arjun (pip) | ❌ |
| initial_fingerprinting | 5006 | Flask | Go, httpx | ❌ |
| page_identifier | 5009 | Flask, selenium, beautifulsoup4, colorama | ChromeDriver | ✅ |
| reflected_parameter_check | 5122 | Flask, selenium, beautifulsoup4, colorama | ChromeDriver | ✅ |
| tech_fingerprinting | 6000 | Flask, requests, Wappalyzer | - | ❌ |
| public_parameters | 6666 | Flask, requests | - | ❌ |
| directory_search | 8000 | Flask, requests | dirsearch, git | ❌ |
| basic_security_scan | 8001 | Flask, requests | nuclei, Go | ❌ |
| api_enumeration | 8002 | Flask, requests | xnlinkfinder | ❌ |
| js_analysis | 8005 | Flask, requests, selenium, beautifulsoup4 | ChromeDriver | ✅ |
| security_scanner | 9998 | Flask | wapiti3 | ❌ |
| launcher | 19000 | Flask | all services | N/A |
| pipeline | - | requests, json | all services | N/A |

---

## 🚀 Installation Quick Start

### Automatic Installation
```bash
python setup.py
```

### Manual Installation

#### Step 1: Python Packages
```bash
pip install -r requirements.txt
```

#### Step 2: Go Installation
- Download & install from https://go.dev/dl/
- Verify: `go version`

#### Step 3: Go Tools
```bash
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/v2/cmd/httpx@latest
```

#### Step 4: ChromeDriver
1. Check Chrome version: Chrome → About
2. Download from https://chromedriver.chromium.org/downloads
3. Add to system PATH or specify location

#### Step 5: Optional Tools
```bash
pip install wapiti3 xnlinkfinder
git clone https://github.com/maurosoria/dirsearch.git
```

---

## ✅ Verification Checklist

```powershell
# Python Version
python --version                 # Should be 3.8+

# Python Packages
pip show Flask                   # Should exist
pip show requests                # Should exist
pip show selenium                # Should exist

# External Tools
go version                       # Should be 1.17+
nuclei -version                  # Should show version
httpx -version                   # Should show version
chromedriver --version           # Should show version

# Services
python launcher.py               # Should start all services
# Check: http://127.0.0.1:19000
```

---

## 📋 Minimal vs Full Installation

### Minimal (Core Only)
```bash
pip install Flask requests beautifulsoup4 selenium dnspython Sublist3r
# Install: Go, ChromeDriver
```
- Can run basic enumeration
- Limited scanning capabilities

### Full (Recommended)
```bash
pip install -r requirements.txt
# Install all external tools
```
- All features enabled
- Full vulnerability scanning
- Technology fingerprinting
- Parameter discovery
- Security analysis

---

## 🔍 Service Dependencies Graph

```
┌─────────────────────────────────────────────────────────┐
│ SUBDOMAIN ENUMERATION (5000)                            │
│ Dependency: None                                         │
│ Provides: Subdomain list                                │
└─────────────────────┬───────────────────────────────────┘
                      │
        ┌─────────────┼─────────────┬──────────────────┐
        │             │             │                  │
        ▼             ▼             ▼                  ▼
   DIRECTORY    TECH FP        BASIC SEC         API ENUM
   SEARCH(8000) (6000)         SCAN(8001)       (8002)
   Depends: Sub Depends: Sub  Depends: Sub    Depends: Sub
   
        │
        ├─────────────────┬──────────────────┬─────────┐
        │                 │                  │         │
        ▼                 ▼                  ▼         ▼
    PAGE ID         SECRET PARAMS       SENSITIVE  JS ANALYSIS
    (5009)          (5004)              PATHS      (8005)
    Depends:Dir    Depends:Dir         (5001)     Depends:Sub
                        │               Depends:
                        │               Dir
                        ▼
                    REFLECTED
                    PARAMS(5122)
                    Depends:Secret
                        │
                        ▼
                    SECURITY SCAN
                    (9998)
                    Depends:Reflected
```

---

## 💾 Output Locations

- **Main Report:** `final_results/<domain>_doomscope_report.json`
- **Subdomain Results:** `final_results/subdomains_<domain>.json`
- **Directory Search:** `directory_search/results/<domain>/`
- **Nuclei Results:** `basic_security_scan/nuclei_results/`
- **JS Analysis:** `js_analysis/results_js/`
- **API Results:** `api_enum/api_results/`
- **Secret Params:** `secret_parameters/arjun_results/`

---

## 🛠️ Troubleshooting

### Problem: "No module named 'X'"
```bash
pip install -r requirements.txt --upgrade
```

### Problem: "Command not found: nuclei"
```bash
# Ensure Go is installed
go version

# Install nuclei
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Add to PATH
echo $PATH  # Linux/macOS
$env:PATH  # Windows
```

### Problem: "Chrome driver issues"
```bash
# Download correct version matching your Chrome
chrome://version/  # Check in Chrome

# Download from: https://chromedriver.chromium.org/downloads
# Extract to: C:\Program Files\ (Windows) or /usr/local/bin (Linux)
```

### Problem: "Port already in use"
```bash
# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Linux/macOS
lsof -i :5000
kill -9 <PID>
```

---

## 📚 Documentation Files

- **QUICK_INSTALL.md** - 5-minute setup guide
- **SERVICES_REQUIREMENTS.md** - Detailed service documentation
- **REQUIREMENTS_CHECKLIST.md** - Complete checklist
- **REQUIREMENTS_SUMMARY.md** - This file

---

## 🎯 Next Steps

1. ✅ Install Python packages: `pip install -r requirements.txt`
2. ✅ Install Go and tools
3. ✅ Download ChromeDriver
4. ✅ Run: `python launcher.py`
5. ✅ Run: `python doomscope_pipeline.py`
6. ✅ Check results in `final_results/`

---

## 📞 Support

For detailed information about specific services:
- See `SERVICES_REQUIREMENTS.md`

For troubleshooting:
- See `REQUIREMENTS_CHECKLIST.md`

For quick setup:
- See `QUICK_INSTALL.md`

---

**Version:** 1.0  
**Last Updated:** 2025-12-21  
**Status:** Ready for Production
