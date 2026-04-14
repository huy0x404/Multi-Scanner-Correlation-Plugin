# Nikto Commands & Google Drive Transfer Guide

## For eLibraryofVKU Target (10.60.68.76)

### Quick Start Commands

**Basic scan:**
```bash
nikto -h http://10.60.68.76/eLibraryofVKU -Format json -output /tmp/nikto_elibrary.json
```

**Aggressive scan (more findings):**
```bash
nikto -h http://10.60.68.76/eLibraryofVKU -Cgidirs all -ignore 404 -Format json -output /tmp/nikto_elibrary_agg.json
```

**With timeout (if server slow):**
```bash
nikto -h http://10.60.68.76/eLibraryofVKU -Timeout 10 -Format json -output /tmp/nikto_elibrary.json
```

**Scan + upload to Google Drive (automated):**
```bash
nikto -h http://10.60.68.76/eLibraryofVKU -Format json -output /tmp/nikto_elibrary.json && \
rclone copy /tmp/nikto_elibrary.json gdrive:nikto_scans/
```

**Check scan result:**
```bash
cat /tmp/nikto_elibrary.json | head -20
# or
python3 -m json.tool /tmp/nikto_elibrary.json | head -30
```

---

## Part 1: Nikto Scan Commands

### Basic Scan
```bash
nikto -h http://192.168.1.10:80 -Format json -output /tmp/nikto.json
```

### Multiple Ports
```bash
nikto -h 192.168.1.10 -p 80,443,8080 -Format json -output /tmp/nikto_multi.json
```

### Aggressive Scan
```bash
nikto -h http://192.168.1.10 -Cgidirs all -ignore 404 -Format json -output /tmp/nikto_agg.json
```
- `-Cgidirs all`: Scan all CGI directories (more findings, slower)
- `-ignore 404`: Skip 404 errors (faster)

### Tuned Scan (Select specific checks)
```bash
nikto -h http://192.168.1.10 -Tuning 1,2,3,4 -Format json -output /tmp/nikto_tuned.json
```

Tuning options:
- `1`: Interesting Files, `2`: Misconfiguration, `3`: Information Disclosure
- `4`: Injection (XSS/SQLi), `5`: Remote File Retrieval, `6`: DoS
- `a`: All (default)

### HTTPS/SSL
```bash
nikto -h https://192.168.1.10:443 --ignore-cert-errors -Format json -output /tmp/nikto_ssl.json
```

### With Authentication
```bash
# Username:Password
nikto -h http://192.168.1.10 -id "user:pass" -Format json -output /tmp/nikto_auth.json

# Cookie
nikto -h http://192.168.1.10 -cookie "sessionid=abc123" -Format json -output /tmp/nikto.json
```

### With Proxy
```bash
nikto -h http://192.168.1.10 -useproxy http://proxy:8080 -Format json -output /tmp/nikto.json
```

### Slow Server (High Timeout)
```bash
nikto -h http://192.168.1.10 -Timeout 10 -PluginTimeout 20 -Format json -output /tmp/nikto.json
```

### Batch Script (Multiple Targets)
```bash
#!/bin/bash
for target in 192.168.1.10 192.168.1.11 192.168.1.12; do
  nikto -h http://$target:80 -Format json -output /tmp/nikto_${target}.json
done
```

### Quick Commands (Copy/Paste Ready)
```bash
# Basic + output
nikto -h http://192.168.1.10:80 -Format json -output /tmp/nikto.json

# Multiple ports
nikto -h 192.168.1.10 -p 80,443,8080,8088 -Format json -output /tmp/nikto_multi.json

# Aggressive
nikto -h 192.168.1.10 -Cgidirs all -ignore 404 -Format json -output /tmp/nikto_agg.json

# HTTPS
nikto -h https://192.168.1.10:443 --ignore-cert-errors -Format json -output /tmp/nikto_ssl.json

# Text output (readable)
nikto -h http://192.168.1.10 -format txt -output /tmp/nikto.txt

# Screen output (verbose)
nikto -h http://192.168.1.10 -display V
```

---

## Part 2: Google Drive Transfer (Ubuntu → Windows)

### Ubuntu: Upload to Google Drive

#### Option A: Using Rclone (Recommended - Automatic)

**First time setup:**
```bash
sudo apt install rclone
rclone config

# Select: Google Drive
# When asked, OAuth login via browser with Google account
# Save config as "gdrive"
```

**Upload file:**
```bash
# Run scan
nikto -h http://192.168.1.10:80 -Format json -output /tmp/nikto.json

# Upload to Drive
rclone copy /tmp/nikto.json gdrive:nikto_scans/

# Verify
rclone ls gdrive:nikto_scans/
```

#### Option B: Using gdrive CLI
```bash
# Install
curl -O https://raw.githubusercontent.com/prasmussen/gdrive/master/resources/install.sh
chmod +x install.sh && ./install.sh

# Login (first time)
gdrive about

# Upload
gdrive upload /tmp/nikto.json
```

#### Option C: Manual Upload (Web UI)
1. Go to https://drive.google.com
2. Create folder "nikto_scans"
3. Upload file manually: New → File upload
4. Select `/tmp/nikto.json`

---

### Windows: Download from Google Drive

#### Option A: Browser (Manual)
1. Go to https://drive.google.com
2. Find folder "nikto_scans"
3. Right-click file → Download
4. Move to: `D:\CODE_WORD\Multi-Scanner Correlation Plugin\out\nikto_export.json`

```powershell
Move-Item "$env:USERPROFILE\Downloads\nikto_export.json" `
  "D:\CODE_WORD\Multi-Scanner Correlation Plugin\out\"
```

#### Option B: Rclone (Automatic)
```powershell
# First time setup
# Download rclone: https://downloads.rclone.org/rclone-latest-windows-amd64.zip
# Extract to C:\rclone
# Run: C:\rclone\rclone.exe config

# Download file
C:\rclone\rclone.exe copy gdrive:nikto_scans `
  "D:\CODE_WORD\Multi-Scanner Correlation Plugin\out\"

# Verify
Get-ChildItem "D:\CODE_WORD\Multi-Scanner Correlation Plugin\out\nikto_export.json"
```

---

## Part 3: Full Workflow

### Manual (Quick)
```bash
# Ubuntu: Scan + Upload
nikto -h http://192.168.1.10:80 -Format json -output /tmp/nikto.json
# Go to https://drive.google.com → Upload manually
# Download from Drive
powershell
nikto -h http://192.168.1.10:80 -Format json -output /tmp/nikto.json && \
rclone copy gdrive:nikto_scans D:\CODE_WORD\...\out\ ; `| Empty Nikto output | Check target is reachable: `curl http://192.168.1.10:80` |
| Parser rejects file | Ensure JSON valid: `python3 -m json.tool /tmp/nikto.json` |
nikto -h http://192.168.1.10:80 -Format json -output /tmp/nikto_${TIMESTAMP}.json && \
rclone copy /tmp/nikto_${TIMESTAMP}.json gdrive:nikto_scans/
## Quick Reference
### Commands (Copy/Paste)
nikto -h http://TARGET:80 -Format json -output /tmp/nikto.json
# Aggressive
# With auth
**Ubuntu - Upload:**
# Rclone
rclone copy /tmp/nikto.json gdrive:nikto_scans/
# Verify
# Download
rclone copy gdrive:nikto_scans ".\out\" 
& ".\.venv\Scripts\python.exe" -m mscp.cli report --nikto ".\out\nikto_export.json" --out ".\out\report.json"
# Open dashboard
& ".\.venv\Scripts\python.exe" -m mscp.cli dashboard --report ".\out\report.json" --port 8787 --no-browser

Open browser: `http://127.0.0.1:8787`
