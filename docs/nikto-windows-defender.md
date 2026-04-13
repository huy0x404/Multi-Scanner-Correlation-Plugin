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
