# DoomScope - Complete Requirements Checklist

## Python Packages (from requirements.txt)
✓ Flask>=2.0
✓ requests>=2.25
✓ urllib3>=1.26
✓ beautifulsoup4>=4.9
✓ lxml>=4.6
✓ selenium>=4.0
✓ httpx>=0.24.0
✓ Sublist3r
✓ waybackpy>=3.2
✓ dnspython>=2.0
✓ tldextract>=3.0
✓ arjun
✓ python-Wappalyzer>=6.0
✓ colorama>=0.4
✓ psycopg>=3.0 (optional)

## External Tools & Dependencies

### Required for Core Functionality
1. **Python 3.8+** (Minimum version)
2. **ChromeDriver** (For Selenium browser automation)
   - Download: https://chromedriver.chromium.org/
   - Must match your Chrome/Chromium version
   - Add to system PATH or specify location in code

3. **Go 1.17+** (For nuclei, httpx, and other tools)
   - Download: https://go.dev/dl/

### Specific Service Dependencies

#### Subdomain & DNS Enumeration
- `dnspython` ✓ (Python package)
- `tldextract` ✓ (Python package)
- `waybackpy` ✓ (Python package)
- `Sublist3r` ✓ (Python package)

#### Directory Search / Brute-Force
- `dirsearch` (Auto-cloned or manually installed)
  - Git: https://github.com/maurosoria/dirsearch.git
  - OR: pip install dirsearch

#### Parameter Discovery
- `arjun` ✓ (Python package - auto-installs if missing)

#### Technology Fingerprinting
- `python-Wappalyzer` ✓ (Python package)
- `httpx v2` (External tool)
  - Install: go install github.com/projectdiscovery/httpx/v2/cmd/httpx@latest

#### Vulnerability Scanning
- `nuclei` (External tool)
  - Install: go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
  - Includes: nuclei-templates (included in repo)

- `wapiti3` (Optional but recommended)
  - Install: pip install wapiti3

#### Browser Automation
- `selenium` ✓ (Python package)
- `ChromeDriver` (External tool)
- `beautifulsoup4` ✓ (Python package)

#### API Enumeration
- `xnlinkfinder` (Optional)
  - Install: pip install xnlinkfinder
  - OR: git clone https://github.com/xnl-h4ck3r/xnlinkfinder.git

## Installation Methods

### Method 1: Automated Setup (Recommended)
```bash
cd c:\laragon\www\doomscope
python setup.py
```

### Method 2: Manual Installation

#### Step 1: Python Packages
```bash
pip install -r requirements.txt
```

#### Step 2: Download ChromeDriver
1. Go to https://chromedriver.chromium.org/
2. Check your Chrome version: Chrome menu → About Google Chrome
3. Download matching ChromeDriver
4. Extract and add to PATH (or note the location)

#### Step 3: Install Go (if not already installed)
- Download from https://go.dev/dl/
- Follow installation instructions for your OS

#### Step 4: Install Go-based Tools
```bash
# Nuclei - Vulnerability Scanner
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# httpx - HTTP Probe Tool
go install github.com/projectdiscovery/httpx/v2/cmd/httpx@latest
```

#### Step 5: Optional Tools
```bash
# dirsearch (if not auto-cloned)
git clone https://github.com/maurosoria/dirsearch.git directory_search/tools/dirsearch

# wapiti3 (recommended for security scanning)
pip install wapiti3

# xnlinkfinder (for API enumeration)
pip install xnlinkfinder
```

## Platform-Specific Notes

### Windows
- Use PowerShell or CMD for commands
- May need to set execution policy: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned`
- ChromeDriver: Download .exe or .zip
- Go: Use installer from go.dev/dl
- Git: Required for cloning repositories

### Linux/macOS
- Use bash or zsh
- Go: Use package manager or download from go.dev/dl
- ChromeDriver: Download appropriate binary
- Git: Usually pre-installed, or `apt install git` / `brew install git`

## Verification Commands

```bash
# Check Python packages
pip list | grep -E "Flask|requests|beautifulsoup4|selenium"

# Check Go tools
nuclei -version
httpx -version

# Check external tools
chromedriver --version
dirsearch --help
wapiti -h
```

## Service Startup & Testing

### Start All Services
```bash
python launcher.py
# Services start on ports: 5000, 5001, 5002, 5003, 5004, 5006, 5009, 5122, 6000, 6666, 6667, 7002, 7006, 7072, 8000, 8001, 8002, 8005, 9998
# Dashboard: http://127.0.0.1:19000
```

### Run Pipeline Scan
```bash
python doomscope_pipeline.py
# When prompted, enter target domain (e.g., example.com)
```

## Troubleshooting

### ChromeDriver Issues
- **Error:** "chromedriver not found"
  - Solution: Download from chromedriver.chromium.org, ensure version matches Chrome
  
- **Error:** "Chrome version mismatch"
  - Solution: Check Chrome version and download matching ChromeDriver

### Nuclei Issues
- **Error:** "nuclei command not found"
  - Solution: Ensure Go is installed, run: `go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest`

- **Error:** "No templates found"
  - Solution: Update templates: `nuclei -update-templates`

### Selenium Issues
- **Error:** "selenium.common.exceptions.WebDriverException"
  - Solution: Ensure ChromeDriver is installed and in PATH

### Port Already in Use
- **Error:** "Address already in use"
  - Solution: Change port in service config or kill existing process
  - Windows: `netstat -ano | findstr :5000` then `taskkill /PID <pid>`
  - Linux/macOS: `lsof -i :5000` then `kill -9 <pid>`

## Final Checklist

- [ ] Python 3.8+ installed
- [ ] All Python packages installed: `pip install -r requirements.txt`
- [ ] Go 1.17+ installed
- [ ] ChromeDriver downloaded and in PATH
- [ ] nuclei installed: `go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest`
- [ ] httpx installed: `go install github.com/projectdiscovery/httpx/v2/cmd/httpx@latest`
- [ ] dirsearch available (auto-cloned or installed)
- [ ] wapiti3 installed: `pip install wapiti3`
- [ ] All services start without errors
- [ ] API endpoints responding on their ports

## Support & Documentation

For detailed service documentation, see: `SERVICES_REQUIREMENTS.md`

For quick setup without manual configuration:
```bash
python setup.py
```
