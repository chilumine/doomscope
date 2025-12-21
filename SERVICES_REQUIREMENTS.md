# DoomScope - Services & Requirements Documentation

## Python Requirements

All Python dependencies are listed in `requirements.txt`. Install them with:

```bash
pip install -r requirements.txt
```

## Services Overview & Individual Requirements

### 1. **Subdomain Enumeration** (`subdomain_enum`)
- **Port:** 5000
- **Endpoint:** `/scan`
- **Python Imports:**
  - `flask`, `requests`, `json`, `re`
  - `subprocess`, `shutil`, `os`, `sys`
  - `concurrent.futures` (ThreadPoolExecutor)
  - `dnspython` (DNS queries)
  - `tldextract` (Domain parsing)
  - `waybackpy` (Wayback Machine API)
  - `Sublist3r` (Subdomain enumeration)

- **External Tools:** None required (all Python-based)

---

### 2. **Tech Fingerprinting** (`tech_fingerprinting`)
- **Port:** 6000
- **Endpoint:** `/techscan`
- **Python Imports:**
  - `flask`, `requests`, `json`, `re`
  - `subprocess`, `sys`, `os`
  - `concurrent.futures` (ThreadPoolExecutor)
  - `urllib3` (HTTP utilities)
  - `python-Wappalyzer` (Technology detection)
  - Calls to `subdomain_enum` service

- **External Tools:** None required

---

### 3. **Sensitive Path Enumeration** (`sensitive_path_enum`)
- **Port:** 5001
- **Endpoint:** `/scan`
- **Python Imports:**
  - `flask`, `requests`, `json`, `re`
  - `os`
  - Reads patterns from `patterns.json`
  - Calls to `directory_search` service

- **External Tools:** None required

---

### 4. **Sensitive Login Enumeration** (`sensitive_login_enum`)
- **Port:** 5002
- **Endpoint:** `/scan`
- **Python Imports:**
  - `flask`, `requests`, `json`, `re`
  - `os`
  - `beautifulsoup4` (HTML parsing)
  - Calls to `directory_search` service

- **External Tools:** None required

---

### 5. **Archived Contents** (`archived_contents`)
- **Port:** 5003
- **Endpoint:** `/scan`
- **Python Imports:**
  - `flask`, `requests`, `json`, `re`
  - `os`
  - Searches Wayback Machine CDX API
  - Pattern matching for sensitive data

- **External Tools:** None required

---

### 6. **Secret Parameters** (`secret_parameters`)
- **Port:** 5004
- **Endpoint:** `/scan`
- **Python Imports:**
  - `flask`, `json`, `re`, `os`
  - `subprocess` (runs Arjun)
  - `shutil`, `time`
  - `concurrent.futures` (ThreadPoolExecutor)
  - `arjun` (Parameter discovery)
  - Reads from `directory_search` results

- **External Tools:**
  - **arjun** - Parameter discovery tool
    ```bash
    pip install arjun
    # Or will auto-install if missing
    ```

---

### 7. **Directory Search** (`directory_search`)
- **Port:** 8000
- **Endpoint:** `/run`
- **Python Imports:**
  - `flask`, `requests`, `json`
  - `subprocess`, `shutil`, `os`, `sys`
  - `pathlib` (Path handling)
  - `concurrent.futures` (ThreadPoolExecutor)
  - Calls to `subdomain_enum` service

- **External Tools:**
  - **dirsearch** - Directory brute-forcing
    ```bash
    # Option 1: System installation
    git clone https://github.com/maurosoria/dirsearch.git
    
    # Option 2: pip installation
    pip install dirsearch
    
    # Will auto-clone if not found
    ```
  - **Python dependencies for dirsearch:**
    - psycopg (for database support)

---

### 8. **Initial Fingerprinting** (`initial_fingerprinting`)
- **Port:** 5006
- **Endpoint:** `/scan`
- **Python Imports:**
  - `flask`, `subprocess`, `shlex`
  - `shutil`, `os`, `sys`, `platform`

- **External Tools:**
  - **Go** (required)
    ```bash
    https://go.dev/dl/
    ```
  - **httpx v2** (HTTP probe)
    ```bash
    go install github.com/projectdiscovery/httpx/v2/cmd/httpx@latest
    ```

---

### 9. **Page Identifier** (`page_identifier`)
- **Port:** 5009
- **Endpoint:** `/scan`
- **Python Imports:**
  - `flask`, `request`, `json`, `re`, `os`, `sys`
  - `beautifulsoup4` (HTML parsing)
  - `selenium` + `webdriver` (Browser automation)
  - `selenium.webdriver.chrome.options`
  - `concurrent.futures` (ThreadPoolExecutor)
  - `colorama` (Terminal colors)
  - Reads from `directory_search` results

- **External Tools:**
  - **ChromeDriver** - Chrome browser automation driver
    ```
    Download from: https://chromedriver.chromium.org/
    Must match your Chrome version
    ```

---

### 10. **JS Analysis** (`js_analysis`)
- **Port:** 8005
- **Endpoint:** `/run`
- **Python Imports:**
  - `flask`, `request`, `json`
  - `os`, `re`, `pathlib`
  - `urllib.parse` (URL parsing)
  - `requests` (HTTP requests)
  - `beautifulsoup4` (HTML parsing)
  - `selenium` + Chrome options (Browser automation)
  - `concurrent.futures` (ThreadPoolExecutor)
  - Calls to `subdomain_enum` service

- **External Tools:**
  - **ChromeDriver** (same as Page Identifier)

---

### 11. **Reflected Parameter Check** (`reflected_parameter_check`)
- **Port:** 5122
- **Endpoint:** `/reflect-scan`
- **Python Imports:**
  - `flask`, `request`, `json`
  - `os`, `random`, `string`
  - `urllib.parse` (URL manipulation)
  - `beautifulsoup4` (HTML parsing)
  - `selenium` + Chrome options (Browser automation)
  - `concurrent.futures` (ThreadPoolExecutor)
  - `colorama` (Terminal colors)
  - Reads from `secret_parameters` results

- **External Tools:**
  - **ChromeDriver** (same as Page Identifier)

---

### 12. **Basic Security Scan** (`basic_security_scan`)
- **Port:** 8001
- **Endpoint:** `/run`
- **Python Imports:**
  - `flask`, `request`, `json`
  - `os`, `sys`, `re`, `shutil`
  - `subprocess`, `pathlib`
  - `concurrent.futures` (ThreadPoolExecutor)
  - `requests`
  - Calls to `subdomain_enum` service

- **External Tools:**
  - **nuclei** - Vulnerability scanner with templates
    ```bash
    # For Linux/macOS:
    go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    
    # For Windows: Download pre-built binary or use WSL
    ```
  - **nuclei-templates** (included in repo)

---

### 13. **API Enumeration** (`api_enum`)
- **Port:** 8002
- **Endpoint:** `/run`
- **Python Imports:**
  - `flask`, `request`, `json`
  - `subprocess`, `re`, `pathlib`
  - `urllib.parse` (URL handling)
  - `requests`
  - Calls to `subdomain_enum` service

- **External Tools:**
  - **xnlinkfinder** - API endpoint extractor
    ```bash
    pip install xnlinkfinder
    # OR
    git clone https://github.com/xnl-h4ck3r/xnlinkfinder.git
    ```

---

### 14. **Security Scanner (Final)** (`security_scanner`)
- **Port:** 9998
- **Endpoint:** `/scan`
- **Python Imports:**
  - `flask`, `request`, `json`
  - `subprocess`, `re`, `os`
  - Reads from `reflected_parameter_check` results

- **External Tools:**
  - **wapiti** - Web vulnerability scanner
    ```bash
    pip install wapiti3
    ```

---

## Installation Instructions

### Step 1: Install Python Dependencies

```bash
cd c:\laragon\www\doomscope
pip install -r requirements.txt
```

### Step 2: Install External Tools

#### Option A: Linux/macOS
```bash
# Install Go (if not already installed)
# Download from https://go.dev/dl/

# Install nuclei
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Install httpx
go install github.com/projectdiscovery/httpx/v2/cmd/httpx@latest

# Install dirsearch
git clone https://github.com/maurosoria/dirsearch.git

# Install wapiti
pip install wapiti3

# Download ChromeDriver
# https://chromedriver.chromium.org/
```

#### Option B: Windows (PowerShell)
```powershell
# Install Go
# Download from https://go.dev/dl/ and run installer

# Install nuclei (requires Go)
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Install httpx
go install github.com/projectdiscovery/httpx/v2/cmd/httpx@latest

# Install dirsearch
git clone https://github.com/maurosoria/dirsearch.git

# Install wapiti
pip install wapiti3

# Download ChromeDriver
# https://chromedriver.chromium.org/
# Extract to PATH or specify in code
```

### Step 3: Verify Installations

```bash
# Check Python packages
pip list | grep -E "Flask|requests|beautifulsoup4|selenium|dnspython|Sublist3r|Wappalyzer"

# Check external tools
nuclei -version
httpx -version
dirsearch --version
wapiti -h
which chromedriver  # Linux/macOS
where chromedriver  # Windows
```

---

## Service Dependencies Map

```
subdomain_enum (5000)
    ↓ (provides subdomains to)
    ├→ directory_search (8000)
    │   ├→ secret_parameters (5004)
    │   │   └→ reflected_parameter_check (5122)
    │   │       └→ security_scanner (9998) [final]
    │   ├→ page_identifier (5009)
    │   ├→ sensitive_path_enum (5001)
    │   └→ sensitive_login_enum (5002)
    ├→ tech_fingerprinting (6000)
    ├→ basic_security_scan (8001) [nuclei]
    ├→ api_enum (8002)
    └→ js_analysis (8005)

archived_contents (5003) [Wayback Machine]
initial_fingerprinting (5006) [httpx]
public_parameters (6666) [api_enum variant]
```

---

## Quick Start Command

```bash
# Terminal 1: Start all services
python launcher.py

# Terminal 2: Run pipeline scan (after launcher is ready)
python doomscope_pipeline.py
# Enter domain when prompted
```

---

## Troubleshooting

### ChromeDriver Issues
- Download the correct version matching your Chrome browser
- Add to PATH or specify full path in selenium code

### nuclei Errors
- Requires Go 1.17+ installed
- Update templates: `nuclei -update-templates`

### arjun Issues
- Manually install if auto-install fails: `pip install arjun`
- May require specific Python version compatibility

### Subprocess Timeouts
- Increase timeout values in service files if running on slow systems
- Increase `MAX_WORKERS` if you have more CPU cores

---

## Final Checklist

- [ ] Python 3.8+ installed
- [ ] All Python packages from `requirements.txt` installed
- [ ] Go 1.17+ installed (for nuclei & httpx)
- [ ] nuclei installed and in PATH
- [ ] httpx v2 installed and in PATH
- [ ] dirsearch cloned or installed
- [ ] wapiti3 installed
- [ ] ChromeDriver downloaded and in PATH
- [ ] All services verified to start without errors
