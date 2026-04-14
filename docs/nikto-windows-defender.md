# Huong Dan Nikto Tren Windows (Defender Van Bat)

Tai lieu nay tong hop dung luong loi thuong gap khi cai Nikto tren Windows:

- `nikto.pl` bi Defender quarantine hoac xoa
- Nikto bao thieu module Perl (`XML::Writer`)
- Khong ket noi duoc target test

Muc tieu:

- Van giu Microsoft Defender bat
- Cai Nikto on dinh, khong bi xoa lai
- Scan duoc website local va xuat JSON de dua vao du an nay

## 1) Chuan Bi Thu Muc

Nen dung thu muc rieng cho cong cu security:

```powershell
New-Item -ItemType Directory -Force D:\Tools | Out-Null
```

## 2) Them Exclusion Dung Cach (Khong Tat Defender)

Vao:

- Windows Security
- Virus and threat protection
- Manage settings
- Exclusions
- Add or remove exclusions

Them exclusion cho:

- `D:\Tools\nikto`

Luu y:

- Nen exclusion hep (thu muc Nikto), khong nen exclusion ca o D:.
- Sau khi them exclusion, Defender van bao ve cac thu muc khac.

## 3) Kiem Tra Va Restore File Bi Quarantine

Vao:

- Windows Security
- Virus and threat protection
- Protection history

Neu thay su kien lien quan `nikto.pl`:

- Chon muc do
- Bam `Restore`

Neu khong restore duoc, clone lai sau khi da them exclusion.

## 4) Cai Lai Sach Nikto

```powershell
Set-Location D:\
if (Test-Path D:\Tools\nikto) { Remove-Item D:\Tools\nikto -Recurse -Force }
git clone https://github.com/sullo/nikto.git D:\Tools\nikto
Set-Location D:\Tools\nikto\program
Get-ChildItem
```

Ban phai thay file `nikto.pl` trong thu muc `program`.

## 5) Cai Perl Runtime (Neu Chua Co)

Nikto can Perl. Kiem tra:

```powershell
perl -v
```

Neu chua co Perl, cai Strawberry Perl roi mo lai terminal.

## 6) Unblock File (Neu Can)

Neu file vua tai ve bi danh dau block:

- Right-click `nikto.pl` -> Properties -> Unblock -> Apply

Hoac PowerShell:

```powershell
Unblock-File D:\Tools\nikto\program\nikto.pl
```

## 7) Chay Thu Nikto

```powershell
perl D:\Tools\nikto\program\nikto.pl -h
```

Ky vong:

- Hien thong tin options cua Nikto (khong con loi module).

## 8) Fix Loi `Required module not found: XML::Writer`

Neu gap loi:

```text
ERROR: Required module not found: XML::Writer
```

Chay:

```powershell
cpan XML::Writer
```

Neu CPAN hoi cau hinh lan dau, chon auto/yes.

Sau khi cai xong, kiem tra lai:

```powershell
perl D:\Tools\nikto\program\nikto.pl -h
```

Ghi chu:

- Lenh `yes` khong phai lenh mac dinh tren Windows CMD, nen loi `yes is not recognized` la binh thuong.
- Khi da thay `Result: PASS` va `install ... OK` trong CPAN thi module da cai thanh cong.

## 9) Test Target Cong Khai Va Target Local

### Test public (de xac nhan Nikto chay)

```powershell
Set-Location D:\Tools\nikto\program
perl .\nikto.pl -h http://testphp.vulnweb.com -Display V
```

Neu `scanme.nmap.org` bi fail ket noi, thuong la do target/network, khong phai loi cai dat.

### Test website local cua ban

```powershell
Set-Location D:\Tools\nikto\program
perl .\nikto.pl -h http://localhost/eLibraryofVKU -Format json -output "D:\CODE_WORD\Multi-Scanner Correlation Plugin\out\nikto_elibrary.json"
```

## 10) Dua Ket Qua Nikto Vao Du An Nay

```powershell
Set-Location "D:\CODE_WORD\Multi-Scanner Correlation Plugin"
& ".\.venv\Scripts\python.exe" -m mscp.cli report --nikto ".\out\nikto_elibrary.json" --risk-config ".\config\risk_weights.json" --out ".\out\report_nikto.json"
```

## 11) Checklist Chuan Doan Nhanh

Neu chay khong duoc, kiem theo thu tu:

1. `perl -e "print 'OK';"` co in `OK` khong.
2. `perl ...\nikto.pl -h` co hien help khong.
3. Con bi `XML::Writer` khong.
4. Defender con quarantine file trong Protection history khong.
5. Target co mo cong web khong (`curl` hoac browser vao duoc khong).

## 12) Bao Mat Va Pham Vi Su Dung

- Chi scan he thong ban so huu hoac duoc cap phep ro rang.
- Giu Defender bat, chi them exclusion toi thieu.
- Tach thu muc cong cu security khoi source code va du lieu quan trong.

## 13) Khi Nikto Chay Tren Linux/VM: Mang File Ve Windows De Phan Tich

Neu ban scan tren Ubuntu (VirtualBox/WSL/may Linux khac), ban chi can dua file Nikto output ve thu muc `out` tren Windows roi chay `mscp.cli report`.

Project nay chap nhan ca:

- Nikto JSON
- Nikto TXT

### 13.1 Lenh phan tich tren Windows (sau khi da co file)

JSON:

```powershell
Set-Location "D:\CODE_WORD\Multi-Scanner Correlation Plugin"
& ".\.venv\Scripts\python.exe" -m mscp.cli report --nikto ".\out\nikto_export.json" --out ".\out\report_nikto.json"
```

TXT:

```powershell
Set-Location "D:\CODE_WORD\Multi-Scanner Correlation Plugin"
& ".\.venv\Scripts\python.exe" -m mscp.cli report --nikto ".\out\nikto_export.txt" --out ".\out\report_nikto.json"
```

Mo dashboard:

```powershell
& ".\.venv\Scripts\python.exe" -m mscp.cli dashboard --report ".\out\report_nikto.json" --host 127.0.0.1 --port 8787 --no-browser
```

## 14) Phuong Phap A: VirtualBox Shared Folder (khuyen dung)

### 14.1 Tren Windows host

- VM Settings -> Shared Folders -> Add
- Folder Path: `D:\CODE_WORD\Multi-Scanner Correlation Plugin\out`
- Folder Name: `nikto_out`
- Tick: `Auto-mount`, `Make Permanent`

### 14.2 Tren Ubuntu guest

Kiem tra auto-mount:

```bash
ls /media
ls /media/sf_nikto_out
```

Neu chua co, mount tay:

```bash
sudo mkdir -p /mnt/nikto_out
sudo mount -t vboxsf nikto_out /mnt/nikto_out
```

Neu bi permission denied:

```bash
sudo usermod -aG vboxsf $USER
```

Dang xuat dang nhap lai Ubuntu, roi chay scan:

```bash
nikto -h http://<target> -Format json -output /mnt/nikto_out/nikto_export.json
```

## 15) Phuong Phap B: Google Drive (de nhat khi copy tay)

### 15.1 Tren Ubuntu/VM

```bash
nikto -h http://<target> -Format json -output /tmp/nikto_export.json
```

Upload file `/tmp/nikto_export.json` len Google Drive.

### 15.2 Tren Windows

- Tai file tu Drive ve: `D:\CODE_WORD\Multi-Scanner Correlation Plugin\out\nikto_export.json`
- Chay lenh phan tich o muc 13.1

Luu y bao mat:

- Khong upload du lieu nhay cam neu chua ma hoa.
- Dung thu muc Drive private va xoa file sau khi da xu ly.

## 16) Phuong Phap C: SCP/WinSCP qua SSH

### 16.1 Tren Ubuntu/VM

```bash
nikto -h http://<target> -Format json -output /tmp/nikto_export.json
```

### 16.2 Tren Windows (scp)

```powershell
scp <user>@<vm-ip>:/tmp/nikto_export.json "D:\CODE_WORD\Multi-Scanner Correlation Plugin\out\nikto_export.json"
```

Hoac dung WinSCP de keo tha GUI.

## 17) Phuong Phap D: HTTP Server Tam tren VM

Tren Ubuntu/VM:

```bash
cd /tmp
python3 -m http.server 8000
```

Tren Windows:

```powershell
Invoke-WebRequest "http://<vm-ip>:8000/nikto_export.json" -OutFile "D:\CODE_WORD\Multi-Scanner Correlation Plugin\out\nikto_export.json"
```

Sau khi tai xong, tat server tam trong VM (Ctrl+C).

## 18) Checklist Nhanh Truoc Khi Bao Loi Parser

1. File nam dung thu muc `out` trong project.
2. File khong rong (size > 0).
3. Dung duoi `.json` hoac `.txt` cua Nikto.
4. Lenh `mscp.cli report --nikto ...` chay tu dung repo root.
5. Neu dashboard khong hien, mo report JSON trong `out` de check noi dung da tao chua.
