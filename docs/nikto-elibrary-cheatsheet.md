# Quick Cheatsheet: Nikto + Google Drive for eLibraryofVKU

**Target**: http://10.60.68.76/eLibraryofVKU

---

## Ubuntu Commands (Run These First)

### 1) Basic Scan
```bash
nikto -h http://10.60.68.76/eLibraryofVKU -Format json -output /tmp/nikto_elibrary.json
```
**Result**: File at `/tmp/nikto_elibrary.json` (~50-100KB, ~30 sec)

### 2) Check File OK
```bash
ls -lh /tmp/nikto_elibrary.json
python3 -m json.tool /tmp/nikto_elibrary.json | head
```

### 3) Upload to Google Drive (Automated)
```bash
rclone copy /tmp/nikto_elibrary.json gdrive:nikto_scans/
```

### 4) Verify Upload
```bash
rclone ls gdrive:nikto_scans/
```

---

## Windows Commands (After Ubuntu Upload)

### 1) Download from Google Drive
```powershell
rclone copy gdrive:nikto_scans "D:\CODE_WORD\Multi-Scanner Correlation Plugin\out\"
```

### 2) Verify File Downloaded
```powershell
Get-ChildItem "D:\CODE_WORD\Multi-Scanner Correlation Plugin\out\nikto_elibrary.json"
```

### 3) Create Report
```powershell
Set-Location "D:\CODE_WORD\Multi-Scanner Correlation Plugin"
& ".\.venv\Scripts\python.exe" -m mscp.cli report `
  --nikto ".\out\nikto_elibrary.json" `
  --out ".\out\report_elibrary.json"
```

### 4) Open Dashboard
```powershell
& ".\.venv\Scripts\python.exe" -m mscp.cli dashboard `
  --report ".\out\report_elibrary.json" `
  --port 8787 `
  --no-browser
```

**Browser**: `http://127.0.0.1:8787`

---

## Automated One-Liner Commands

### Ubuntu (Scan + Upload, no steps)
```bash
nikto -h http://10.60.68.76/eLibraryofVKU -Format json -output /tmp/nikto_elibrary.json && rclone copy /tmp/nikto_elibrary.json gdrive:nikto_scans/
```

### Windows (Download + Report + Dashboard, no steps)
```powershell
rclone copy gdrive:nikto_scans "D:\CODE_WORD\Multi-Scanner Correlation Plugin\out\" ; cd D:\CODE_WORD\Multi-Scanner\ Correlation\ Plugin ; & ".\.venv\Scripts\python.exe" -m mscp.cli report --nikto ".\out\nikto_elibrary.json" --out ".\out\report_elibrary.json" ; & ".\.venv\Scripts\python.exe" -m mscp.cli dashboard --report ".\out\report_elibrary.json" --port 8787 --no-browser
```

---

## Aggressive Scan (More Findings, Slower ~3-5 min)

### Ubuntu
```bash
nikto -h http://10.60.68.76/eLibraryofVKU -Cgidirs all -ignore 404 -Format json -output /tmp/nikto_elibrary_agg.json && rclone copy /tmp/nikto_elibrary_agg.json gdrive:nikto_scans/
```

### Windows (Same as above, just use the aggressive file)
```powershell
rclone copy gdrive:nikto_scans ".\out\" ; & ".\.venv\Scripts\python.exe" -m mscp.cli report --nikto ".\out\nikto_elibrary_agg.json" --out ".\out\report_elibrary_agg.json" ; & ".\.venv\Scripts\python.exe" -m mscp.cli dashboard --report ".\out\report_elibrary_agg.json" --port 8787 --no-browser
```

---

## Setup (First Time Only)

### Ubuntu: Configure Rclone
```bash
sudo apt install rclone
rclone config
# Select: Google Drive
# Login with Gmail account
# Save config as "gdrive"
```

### Windows: Configure Rclone
```powershell
# Download from: https://downloads.rclone.org/rclone-latest-windows-amd64.zip
# Extract to: C:\rclone
# Run: C:\rclone\rclone.exe config
# Select: Google Drive, login, save
```

---

## Verify Connectivity

```bash
# Ubuntu: Check target is up
curl -v http://10.60.68.76/eLibraryofVKU

# Ubuntu: Test Rclone access
rclone ls gdrive:

# Windows: Test Rclone access
C:\rclone\rclone.exe ls gdrive:
```

---

## File Locations

| System | Path | Description |
|--------|------|-------------|
| Ubuntu | `/tmp/nikto_elibrary.json` | Scan output file |
| Google Drive | `nikto_scans/` | Uploaded files folder |
| Windows | `D:\CODE_WORD\Multi-Scanner Correlation Plugin\out\` | Downloaded files |
| Windows | `D:\CODE_WORD\Multi-Scanner Correlation Plugin\out\report_elibrary.json` | Analysis report |

---

## Common Issues

| Problem | Fix |
|---------|-----|
| Nikto fails to connect | `curl http://10.60.68.76/eLibraryofVKU` to check target |
| Empty JSON file | Increase timeout: `nikto ... -Timeout 15 ...` |
| Rclone upload fails | Run `rclone config` again to re-authenticate |
| Report shows no findings | Check JSON file size > 0: `ls -lh /tmp/nikto_elibrary.json` |
| Dashboard won't open | Port 8787 may be in use: try `--port 8788` |

---

## Expected Timing

- Basic scan: ~30 seconds → ~50KB file
- Aggressive scan: ~3-5 minutes → ~300KB file
- Upload to Drive: ~5-10 seconds
- Download from Drive: ~5-10 seconds
- Report generation: ~5-10 seconds
- Dashboard load: ~2-3 seconds
