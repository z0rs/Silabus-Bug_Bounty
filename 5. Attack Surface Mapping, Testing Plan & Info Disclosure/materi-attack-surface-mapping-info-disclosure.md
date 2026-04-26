# Attack Surface Mapping, Testing Plan & Info Disclosure

## Fokus Materi

Mengubah hasil reconnaissance menjadi attack surface map yang terstruktur dan menyusun testing plan sistematis sebelum memulai vulnerability hunting. Bagian ini juga mencakup teknik informasi disclosure yang sering diremehkan padahal merupakan kelas bug yang valid dan sering muncul di program bug bounty.

## Deskripsi Materi

Setelah fase recon selesai — subdomain ditemukan, teknologi diidentifikasi, endpoint di-map — langkah berikutnya adalah mengorganisir semua informasi tersebut menjadi attack surface map yang actionable. Tanpa ini, researcher cenderung bersifat reactive: menemukan vulnerability secara random tanpa strategi yang sistematis.

Attack surface mapping adalah proses transformasi dari data mentah (subdomain list, tech stack, endpoint list) menjadi struktur yang bisa ditindaklanjuti (priority list, testing plan, vulnerability hypothesis). Researcher yang skilled tahu membedakan mana yang high-value target dan mana yang noise.

Testing plan adalah roadmap yang menentukan:
- Sesi apa yang akan ditest duluan (prioritas)
- Bagaimana approach setiap target berdasarkan tech stack
- Berapa waktu yang dialokasikan per kategori
- Kapan pivot dari satu target ke target lain

Tanpa testing plan, researcher akan spending waktu terlalu lama di target yang tidak promising atau miss target yang sebenarnya valuable.

Info Disclosure adalah kelas vulnerability yang sering undervalued. Banyak researcher tidak memperhitungkan error message, debug endpoint, exposed configuration, atau metadata sebagai bug yang valid. Padahal info disclosure sering menjadi entry point untuk vulnerability yang lebih besar — dan banyak program bounty memberikan severity yang signifikan untuk exposed credentials atau sensitive data.

## Topik Pembahasan

• Attack surface map: cara baca dan interpretasi hasil recon menjadi actionable map
• Kategorisasi endpoint: login, API, admin, upload, search, export, payment
• Prioritisasi target: potensi impact vs kompleksitas (quick win vs deep dive)
• Mapping ke OWASP WSTG: tiap endpoint ke kategori uji yang relevan
• Membuat checklist testing per endpoint (spreadsheet / Notion)
• Time management saat hunting: alokasi waktu per kategori, pivot strategy
• Practice: membuat attack surface map sederhana dari target latihan

[Info Disclosure & Sensitive Data Exposure]
• Error message informatif: stack trace, DB error, path disclosure — cara reproduce
• Debug endpoint terbuka: /debug, /health, /actuator, /phpinfo — cara identify
• Backup & config file: .bak, .old, web.config, .env — fuzzing & validasi
• Directory listing aktif: cek, implikasi, cara report
• Git repo exposed: .git/config, .git/HEAD — dump repository dengan git-dumper
• Metadata dokumen (EXIF, PDF, DOCX): extract username, path, software version
• Cloud storage misconfiguration: S3 bucket public, GCS bucket listing
• Kategorisasi severity info disclosure: kapan P3 vs P5

## Tujuan Pembelajaran

Setelah sesi ini, peserta diharapkan mampu:
1. Membuat attack surface map terstruktur dari hasil recon
2. Mengategorisasi endpoint berdasarkan risk dan complexity
3. Menyusun testing plan dengan time allocation yang realistis
4. Melakukan info disclosure testing secara sistematis
5. Menggunakan OWASP WSTG sebagai testing framework
6. Membuat checklist testing per endpoint
7. Memahami severity assessment untuk info disclosure

## Real Case Bug Bounty Report

- Platform: HackerOne
- Program/Target: Program enterprise (disclosed)
- Jenis vulnerability: Information Disclosure via exposed .git repository
- Link report: https://hackerone.com/reports/XXXXX
- Ringkasan kasus: Researcher menemukan subdomain staging yang expose .git directory lengkap. Dengan git-dumper, researcher mengekstrak entire source code yang mengandung hardcoded database credentials, API keys, dan internal configuration. Tidak ada authentication untuk akses .git, dan subdomain tidak listed di program scope tapi owned oleh target company.
- Root cause: Server misconfiguration, .git folder accessible via web, no authentication, and subdomain not in scope but still company asset.
- Impact: Full source code access + credentials. Severity: High (CVSS 7.5)
- Pelajaran untuk bug hunter: Always check for .git exposure di subdomain yang ditemukan dari CT logs, even jika subdomain tidak di-disclose di scope.

---

- Platform: Bugcrowd
- Program/Target: Program SaaS
- Jenis vulnerability: Exposed Spring Boot Actuator endpoint
- Link report: Public researcher writeup
- Ringkasan kasus: Researcher menemukan /actuator endpoint di API subdomain yang exposed health metrics, env variables, dan dalam beberapa kasus sogar config properties. Actuator dalam kondisi default (tidak dikonfigurasi security-nya) memberikan information seperti: Java version, framework version, internal paths, dan dalam kasus tertentu sensitive config values.
- Root cause: Spring Boot Actuator di-deploy ke production tanpa security configuration. Endpoint yang seharusnya untuk monitoring internal accessible dari public internet tanpa authentication.
- Impact: Information disclosure yang membantu attacker dalam reconnaissance phase. Severity: Medium (CVSS 5.3) — tapi bisa escalate jika actuator menyediakan sensitive endpoints seperti /env atau /heapdump.
- Pelajaran untuk bug hunter: /actuator/info, /actuator/health adalah endpoint yang sering missed. Check semua /actuator/* paths dan test untuk exposure.

---

- Platform: Intigriti
- Program/Target: Program publik
- Jenis vulnerability: Cloud storage (S3 bucket) publicly accessible
- Link report: Researcher disclosed blog
- Ringkasan kasus: Researcher menemukan S3 bucket accessible publicly melalui enumeration subdomain dan guess. Bucket mengandung backup files, configuration backups, dan dalam beberapa kasus user-uploaded documents yang seharusnya private. Researcher melakukan access log untuk document metadata tanpa authentication.
- Root cause: S3 bucket ACL misconfigured — bucket policy allow public access, atau bucket is set to block new public access but existing access still allowed.
- Impact: Privacy breach, sensitive data exposure. Severity: High jika data sensitive, Medium jika generic.
- Pelajaran untuk bug hunter: Cloud storage enumeration adalah bagian critical dari recon. Check untuk S3 bucket patterns (target-com, target-prod, target-backup, dll) dan test public accessibility.

## Analisis Teknis

### Attack Surface Mapping Framework

**Step 1: Data Collection (from Recon)**

Dari hasil recon, kumpulkan:
```
- Subdomain list + IP
- Tech stack per subdomain (nginx, Apache, Node.js, PHP, dll)
- Open ports dan services
- Endpoint list (from dirb/ffuf)
- Technology fingerprints (Wappalyzer, whatweb)
```

**Step 2: Categorization**

Buat spreadsheet dengan columns:

| Subdomain | IP | Tech Stack | Category | Risk Level | Notes |
|-----------|-----|------------|----------|------------|-------|
| api.target.com | 1.2.3.4 | Node.js, Express | API | High | JWT auth, GraphQL |
| admin.target.com | 1.2.3.4 | PHP 7.4, Apache | Admin Panel | Critical | Legacy, no MFA |
| staging.target.com | 5.6.7.8 | Python, Django | Staging | High | .git exposed |
| old.target.com | 9.10.11.12 | PHP 5.6 | Legacy | Critical | Outdated PHP |

**Step 3: Category Classification**

```markdown
Endpoint Categories:

1. Authentication Endpoints
   - Login, register, password reset, MFA
   - Risk: Critical (ATO possible)
   - Test: Auth bypass, credential stuffing, MFA bypass

2. API Endpoints
   - REST API, GraphQL, gRPC
   - Risk: High (BOLA, mass assignment, IDOR)
   - Test: IDOR, auth bypass, rate limiting

3. User-Facing Web App
   - Public pages, profile, settings
   - Risk: Medium-High (XSS, CSRF, Open Redirect)
   - Test: XSS, CSRF, open redirect, business logic

4. Admin Panels
   - Admin dashboard, user management
   - Risk: Critical (if accessible)
   - Test: Auth bypass, IDOR, BFAC

5. File/Upload Features
   - Avatar upload, document upload, file download
   - Risk: Critical (RCE possible)
   - Test: File upload bypass, path traversal

6. Payment/Gateway
   - Checkout, payment processing
   - Risk: Critical (financial fraud)
   - Test: Price manipulation, logic bypass

7. Integration/Webhook
   - Third-party integration, callback URLs
   - Risk: High (SSRF possible)
   - Test: SSRF, webhook abuse
```

**Step 4: Priority Scoring**

Score setiap target berdasarkan:

| Factor | Weight | Score |
|--------|--------|-------|
| Tech stack vulnerability | 25% | Framework lama = higher risk |
| Authentication requirement | 20% | No auth = higher risk |
| Data sensitivity | 25% | Payment/user data = higher risk |
| Scope inclusion | 20% | In-scope = higher priority |
| Complexity | 10% | Simple = higher priority |

```python
# Priority calculation (simplified)
def calculate_priority(subdomain):
    score = 0

    # Tech stack (25%)
    if has_legacy_tech(subdomain): score += 25
    elif has_common_vuln_framework(subdomain): score += 15
    else: score += 5

    # Auth requirement (20%)
    if no_auth(subdomain): score += 20
    elif weak_auth(subdomain): score += 10
    else: score += 5

    # Data sensitivity (25%)
    if has_payment(subdomain): score += 25
    elif has_user_data(subdomain): score += 15
    else: score += 5

    # Scope (20%)
    if in_scope(subdomain): score += 20
    else: score += 0

    # Complexity (10%)
    if simple_app(subdomain): score += 10
    elif standard_app(subdomain): score += 5
    else: score += 2

    return score  # Higher = more priority

# Priority tiers:
# 80-100: Immediate testing
# 50-79: High priority
# 20-49: Medium priority
# 0-19: Low priority / skip
```

### OWASP WSTG Mapping

OWASP Web Security Testing Guide menyediakan framework testing yang komprehensif. Map target ke category:

```markdown
WSTG Category → Target Endpoints → Testing Approach

WSTG-ATHN-01: Authentication Testing
  → Login, MFA, SSO
  → Test: credential stuffing, MFA bypass, session hijacking

WSTG-ATHN-02: Session Management Testing
  → All authenticated endpoints
  → Test: session fixation, token analysis, logout validation

WSTG-IDNT-01: Identify Information Gathering
  → All public endpoints
  → Test: recon techniques, directory enumeration

WSTG-INPV-01: Reflected XSS
  → All input fields
  → Test: XSS payload injection

WSTG-INPV-02: Stored XSS
  → User-generated content endpoints
  → Test: stored payload, comment injection

WSTG-INPV-08: SQL Injection
  → All database-connected endpoints
  → Test: SQLi payloads, union-based, blind

WSTG-BUSLOGIC-01: Business Logic Testing
  → Payment, coupon, workflow endpoints
  → Test: logic bypass, value manipulation

WSTG-ERRHD-01: Error Handling
  → All endpoints
  → Test: trigger errors, analyze responses

WSTG-CONF-02: Fingerprint Web Application
  → All endpoints
  → Test: technology identification
```

### Testing Plan Template

```markdown
# Testing Plan: [Target Program/Asset]

## Date: [Tanggal]
## Researcher: [Nama]
## Total Time Allocation: [X] hours

## Phase 1: Quick Wins (Budget: 20% of time)
### Target: Endpoints dengan highest probability + good impact

| Endpoint | Category | Testing Focus | Estimated Time |
|----------|----------|---------------|----------------|
| /api/ | API | IDOR, BOLA | 30 min |
| /upload | File Upload | Upload bypass | 30 min |
| /api/profile | User Data | IDOR | 20 min |

## Phase 2: Core Testing (Budget: 50% of time)
### Target: Primary attack surface

| Endpoint | Category | Testing Focus | Estimated Time |
|----------|----------|---------------|----------------|
| /admin | Admin | Auth bypass, BFAC | 1 hour |
| /checkout | Payment | Price manipulation | 45 min |
| /search | Search | XSS, SQLi | 1 hour |
| /api/v2 | API v2 | GraphQL, IDOR | 1 hour |

## Phase 3: Deep Dive (Budget: 30% of time)
### Target: Complex vulnerabilities

| Endpoint | Category | Testing Focus | Estimated Time |
|----------|----------|---------------|----------------|
| /oauth/* | OAuth | Token leakage, state bypass | 1.5 hour |
| /api/upload | File API | SSRF, upload chain | 1 hour |
| /internal-api | Internal | SSRF, auth bypass | 1 hour |

## Pivot Strategy
- If no finding after 2 hours in one category → move to next category
- If promising target found → extend time budget to that category
- Document all attempts even if no finding (for future reference)

## End-of-Session Review
- Document all findings
- Note which areas need deeper testing
- Identify new targets from recon results
- Schedule follow-up sessions
```

### Info Disclosure Testing Methodology

**Target 1: Error Messages**

```bash
# Test berbagai input yang trigger error
'  "  \ ; -- OR 1=1
Non-numeric input in numeric field
Overly long input
Special characters
Missing required parameters

# Observe response untuk:
- Stack trace (Java stack trace, Python traceback)
- SQL error messages
- Path disclosure (/var/www/app/...)
- Internal IP/hostname in error
- Debug information

# Tools:
# Burp Suite → HTTP History → filter for error status codes
# ffuf untuk fuzz parameter dan trigger errors
```

**Target 2: Debug & Management Endpoints**

```bash
# Common debug endpoints:
/debug
/actuator
/actuator/health
/actuator/env
/actuator/beans
/actuator/heapdump
/actuator/loggers
/admin/debug
/phpinfo.php
/info
/metrics
/prometheus
/debug/vars
/health
/healthz
/status
/.env
/config
/hudson
/jmx
/trace
/web-console
/ords/*
/swagger-ui.html
/swagger-ui/
/api-docs
/openapi

# Method: Enumerate dengan ffuf
ffuf -w /opt/SecLists/Discovery/Web-Content/quick-test-wordlist.txt \
     -u https://target.com/FUZZ \
     -mc 200,403 \
     -o debug_endpoints.json

# Test untuk:
# Spring Boot: /actuator/env menampilkan env variables
# Apache TomCat: /admin/debug menampilkan application state
# Laravel: /_debugbar membuka debug toolbar
```

**Target 3: Backup & Configuration Files**

```bash
# File extensions untuk fuzzing:
.bak .backup .old .swp .swo .tmp .conf .config .ini
.env .git .git/config .git/HEAD .git/index
.sqldump .sql .db .sqlite
.xml .yaml .yml .json (config files)

# Common paths:
/backup/
/backups/
/db/
/database/
/dump/
/sql/
/config/
/configs/
/tmp/

# Wordlist untuk ffuf:
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-files.txt \
     -u https://target.com/FUZZ \
     -e .bak,.old,.swp,.tmp,.sql,.env,.git \
     -mc 200 \
     -o backup_files.json

# Git exposure detection:
# Test untuk .git/config accessible
curl -I https://target.com/.git/config
# Test untuk directory listing
curl -I https://target.com/.git/
# Dump dengan git-dumper:
git-dumper https://target.com/.git/ /tmp/target-git/
```

**Target 4: Directory Listing**

```bash
# Directory listing aktif terdeteksi dari response yang contain:
# - "Index of /"
# - Parent directory links
# - File listing tanpa template

# Check manually:
curl -s https://target.com/uploads/ | grep -i "index of"
curl -s https://target.com/backup/ | grep -i "index of"

# Test untuk enable directory listing:
# Apache: jika Options Indexes enabled
# Nginx: jika autoindex on

# Impact: Attacker bisa enumerate semua files di directory
```

**Target 5: Cloud Storage**

```bash
# AWS S3 bucket enumeration:
# Pattern: target-bucket, target-prod, target-dev, target-static
# Region: s3.amazonaws.com, s3.[region].amazonaws.com

# Check bucket accessibility:
aws s3 ls s3://target-bucket/ --no-sign-request
curl -s https://target-bucket.s3.amazonaws.com/

# GCP Storage:
# Pattern: target-assets, target-uploads
gsutil ls gs://target-bucket/

# Azure Blob:
# Pattern: targetblob, targetfiles
az storage container list --connection-string "..."

# Test for path traversal in bucket name:
aws s3 ls s3://target-bucket/../other-bucket/
```

**Target 6: Document Metadata**

```bash
# EXIF extraction from images:
exiftool document.pdf
exiftool photo.jpg

# DOCX/XLSX metadata:
# DOCX adalah ZIP file dengan metadata di docProps/core.xml
unzip -p document.docx docProps/core.xml
unzip -p spreadsheet.xlsx docProps/core.xml

# PDF metadata:
pdftk document.pdf dump_data
pdfinfo document.pdf

# Information extracted:
# - Author name (username potential)
# - Software version
# - Created date/location
# - Internal paths
```

### Info Disclosure Severity Matrix

```markdown
| Type | Example | Severity | Bounty Range | Notes |
|------|---------|----------|--------------|-------|
| Exposed credentials | .env with password | Critical | $500-$5,000+ | Direct exploitation path |
| Source code | .git exposed | High | $300-$2,000 | Depends on what's in code |
| Internal IP/hostname | Error messages | Medium | $100-$500 | Helps attacker in recon |
| Software version | Version in header | Low | $50-$200 | Informational only |
| User enumeration | Login tells "user not found" | Medium | $100-$500 | Helps targeted attacks |
| Stack trace | Full Java trace | Medium | $100-$500 | Information disclosure |
| Debug endpoint | /actuator/env | Medium-High | $200-$1,000 | Depends on what's exposed |
| Directory listing | Index of /files | Medium | $100-$500 | Depends on what's listed |
| Cloud storage | Public S3 bucket | High | $300-$3,000 | Depends on data sensitivity |
| Metadata | Author in PDF | Low | $50-$100 | Minimal direct impact |
```

## Praktik Lab Legal

### Lab 1: Build Attack Surface Map

- **Nama lab:** Attack Surface Mapping Exercise
- **Tujuan:** Buat attack surface map dari hasil recon untuk target lab
- **Environment:** Kali Linux, hasil recon dari sesi sebelumnya, spreadsheet/Notion
- **Langkah praktik:**

  1. Ambil hasil recon dari target lab (subdomain list, tech stack, open ports)
  2. Buat spreadsheet dengan columns: subdomain, IP, tech stack, category, risk level
  3. Kategorisasi setiap subdomain:
     - Authentication (login, MFA, password reset)
     - API (REST, GraphQL)
     - Admin (dashboard, user management)
     - File handling (upload, download)
     - Payment (checkout, billing)
  4. Assign priority score (High/Medium/Low) untuk setiap subdomain
  5. Map setiap subdomain ke OWASP WSTG testing category
  6. Buat testing plan: allocate time untuk setiap category

- **Expected result:** Peserta punya structured attack surface map dan testing plan untuk target lab
- **Catatan keamanan:** Lab ini menggunakan hasil recon dari environment authorized. Data recon dari target real harus sudah di-clear dari sensitive information.

### Lab 2: Info Disclosure Hunt

- **Nama lab:** Info Disclosure Investigation
- **Tujuan:** Temukan dan dokumentasikan info disclosure vulnerability di target lab
- **Environment:** Burp Suite, ffuf, target lab
- **Langkah praktik:**

  1. Identifikasi semua potential info disclosure vectors:
     - Error messages (trigger dengan various inputs)
     - Debug endpoints (ffuf untuk common paths)
     - Backup files (fuzz untuk .bak, .env, .git, dll)
     - Directory listing (check common directories)
     - Cloud storage (enumerate S3/GCS buckets)
  2. Untuk setiap vector, document:
     - Endpoint yang tested
     - Method yang digunakan
     - Information yang disclosed
     - Severity assessment
  3. Buat comparison: which info disclosure finding paling valuable?
  4. Write report untuk info disclosure findings

- **Expected result:** Peserta menemukan minimal 5 info disclosure vectors dan membuat laporan untuk masing-masing
- **Catatan keamanan:** Lab ini hanya untuk target authorized. Jangan enumerasi S3 bucket atau test debug endpoints di target real tanpa izin.

### Lab 3: Git Exposure & Source Code Dump

- **Nama lab:** Git Repository Exposure
- **Tujuan:** Identify dan dump exposed Git repository untuk information gathering
- **Environment:** Burp Suite, git-dumper, target lab (atau setup intentionally exposed .git)
- **Langkah praktik:**

  1. Identifikasi target yang potentially expose .git:
     - Staging/dev subdomain
     - Old/unmaintained endpoints
     - Hasil recon dari CT logs
  2. Test untuk .git/config accessibility:
     curl -I https://target.com/.git/config
  3. Test untuk .git directory listing:
     curl -I https://target.com/.git/
  4. Jika exposed, dump repository:
     git-dumper https://target.com/.git/ /tmp/target-git/
  5. Analyze dump:
     - git log → commit history (credentials di commit message?)
     - git diff → source code changes (API keys?)
     - Configuration files → database credentials
  6. Document findings dan information yang bisa di-extract

- **Expected result:** Peserta memahami dampak git exposure dan bisa extract useful information dari dumped repository
- **Catatan keamanan:** Lab ini memerlukan target yang intentionally expose .git. Dalam production, ini adalah vulnerability serius — report segera jika ditemukan di real target.

### Lab 4: Testing Plan Execution

- **Nama lab:** Systematic Vulnerability Testing
- **Tujuan:** Execute testing plan yang sudah dibuat dan dokumentasikan hasil
- **Environment:** Burp Suite, target lab, attack surface map dari Lab 1
- **Langkah praktik:**

  1. Ambil attack surface map dan testing plan dari Lab 1
  2. Execute Phase 1 (Quick Wins): test highest priority endpoints
  3. Document hasil untuk setiap endpoint yang ditest
  4. Jika ditemukan vulnerability → document dengan PoC
  5. Jika tidak ditemukan → note "tested, no finding" untuk avoid duplication
  6. Execute Phase 2 (Core Testing) sesuai plan
  7. Execute Phase 3 (Deep Dive) sesuai plan
  8. Review: apakah semua endpoints sudah ditest? Apakah ada area yang perlu deeper testing?

- **Expected result:** Peserta punya systematic testing record untuk seluruh attack surface target lab
- **Catatan keamanan:** Lab ini menggunakan testing plan untuk organize approach. Pastikan semua testing dilakukan di authorized environment.

## Tools

- **Attack surface mapping:** Spreadsheet, Notion, Obsidian
- **OWASP WSTG:** Framework untuk systematic testing
- **Info disclosure enumeration:** ffuf, dirsearch, Burp Suite
- **Git dumper:** git-dumper, GitHub tools
- **Cloud enumeration:** aws-cli, gsutil, az cli
- **Metadata extraction:** exiftool, pdftk, binwalk
- **Documentation:** Notion, Obsidian, spreadsheets

## Checklist Bug Hunter

- [ ] Buat attack surface map dari hasil recon
- [ ] Kategorisasi semua subdomain dan endpoint
- [ ] Assign priority score untuk setiap target
- [ ] Map target ke OWASP WSTG testing category
- [ ] Buat testing plan dengan time allocation
- [ ] Test error messages untuk stack trace dan information disclosure
- [ ] Fuzz untuk debug endpoints (/debug, /actuator, /phpinfo)
- [ ] Scan untuk backup files (.bak, .env, .git, .sql)
- [ ] Check directory listing di common directories
- [ ] Enumerate cloud storage (S3, GCS, Azure blob)
- [ ] Extract metadata dari documents (EXIF, PDF, DOCX)
- [ ] Document semua info disclosure findings dengan severity
- [ ] Execute testing plan dan track progress
- [ ] Review dan update attack surface map setelah setiap session

## Common Mistakes

1. **Skip attack surface mapping, langsung scanning** — Researcher yang langsung冲向 automated scanner tanpa map sering miss target yang valuable dan waste waktu di target yang low-value.

2. **Tidak menggunakan OWASP WSTG sebagai framework** — Tanpa framework, testing menjadi random dan tidak systematic. WSTG memberikan coverage checklist yang comprehensive.

3. **Melapor info disclosure tanpa dampak yang jelas** — Error message yang hanya显示 "invalid input" tanpa sensitive information akan di-reject atau rated sangat low. Selalu demonstrate impact.

4. **Tidak enumerasi cloud storage** — Banyak researcher yang fokus di web app tapi miss cloud resources yang accessible dan potentially contain sensitive data.

5. **Tidak tracking testing progress** — Tanpa dokumentasi, researcher akan test area yang sama berulang-ulang dan miss areas yang belum ditest.

6. **Abaikan staging/development subdomain** — Subdomain ini sering tidak di-maintain dengan same security standard sebagai production dan bisa punya exposed .git, debug endpoints, atau legacy vulnerabilities.

7. **Tidak membedakan P3 vs P5 info disclosure** — Researcher report semua info disclosure sebagai sama severity. Perlu understand mana yang benar-benar valuable dan mana yang informational only.

## Mitigasi Developer

**Attack Surface Management:**
- Regular asset inventory dan cleanup
- Remove deprecated subdomains dari DNS
- Implementasi automatic discovery untuk shadow IT
- Remove debug endpoints dari production
- Disable directory listing di web server

**Info Disclosure Prevention:**
- Implementasi custom error pages (tidak menampilkan stack trace)
- Disable debug mode di production
- Protect /actuator endpoints dengan authentication atau remove entirely
- Regular scan untuk exposed .git, backup files, config files
- Implementasi security headers (X-Frame-Options, CSP, etc.)
- Monitor untuk credential exposure di GitHub (gunakan GitHub secret scanning)
- Proper S3/GCS bucket ACL configuration (block public access)
- Remove sensitive information dari error messages dan logs
- Implementasi WAF untuk block path enumeration attempts

## Mini Quiz

1. Attack surface map berfungsi untuk:
   a) Menampilkan semua subdomain yang ditemukan
   b) Mengorganisir hasil recon menjadi structured priority list untuk systematic testing
   c) Membuat laporan untuk program owner
   d) Semua jawaban benar

2. OWASP WSTG mapping membantu researcher untuk:
   a) Menggunakan scanner otomatis
   b) Memetakan target ke testing category untuk ensure systematic coverage
   c) Membuat laporan bug bounty
   d) Menemukan vulnerability lebih cepat

3. Info disclosure severity P3 (Medium) biasanya termasuk:
   a) Exposed database credentials
   b) Internal IP address disclosure di error message
   c) Full source code dump via .git exposure
   d) Softwar e version disclosure di header

4. Debug endpoint seperti /actuator/env di Spring Boot bisa disclosure:
   a) Environment variables yang mungkin mengandung secrets
   b) Application configuration
   c) System information
   d) Semua jawaban benar

5. Cloud storage enumeration (S3 bucket) sebaiknya dilakukan dengan:
   a) Langsung scan seluruh AWS IP range
   b) Enumerate menggunakan pattern-based guess dari target company name
   c) Brute force subdomain untuk storage subdomain
   d) Semua jawaban benar

**Kunci Jawaban:** 1-B, 2-B, 3-B, 4-D, 5-B

## Assignment

1. **Attack Surface Map Construction:** Ambil hasil recon dari minimal 2 target berbeda (bisa lab atau disclosed program). Buat attack surface map lengkap untuk masing-masing: subdomain list, tech stack, category, priority, WSTG mapping, dan testing plan. Bandingkan kedua map.

2. **Info Disclosure Audit:** Lakukan info disclosure audit untuk target lab. Include: error messages, debug endpoints, backup files, git exposure, cloud storage, dan metadata. Document findings dan severity untuk masing-masing.

3. **Git Exposure Analysis:** Buat simulasi git exposure scenario. Identifikasi 3 jalur untuk extract useful information dari exposed repository (credentials, API keys, internal paths, source code with vulnerabilities).

4. **Testing Plan Execution:** Execute testing plan untuk target lab berdasarkan attack surface map yang sudah dibuat. Dokumentasikan setiap endpoint yang ditest dan hasil (finding atau no finding). Buat summary report.

5. **OWASP WSTG Coverage Check:** Buat checklist yang memetakan setiap WSTG category ke target di attack surface map. Identifikasi category mana yang sudah ter-cover dan mana yang belum.

## Template Report Bug Bounty

```markdown
# Bug Report: Exposed .git Repository Containing Source Code and Credentials

## Summary
Subdomain staging.target.com expose .git directory yang memungkinkan
attacker mengekstrak entire source code application beserta hardcoded
credentials dan API keys.

## Platform / Program
HackerOne | [Program Name]

## Severity
High | CVSS 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

## Vulnerability Type
Information Disclosure / Sensitive Data Exposure

## Asset / Endpoint
http://staging.target.com/.git/

## Description
The .git directory is accessible via web without authentication.
Attacker bisa menggunakan git-dumper untuk extract entire repository
yang mengandung:
1. Full source code application
2. Database credentials di config files
3. API keys untuk third-party services
4. Internal documentation dan path structure
5. Commit history yang mungkin mengandung sensitive information

Root cause: Git directory not excluded from web root, no server
configuration to block access.

## Steps to Reproduce
1. Identify subdomain from Certificate Transparency logs:
   crt.sh query → found staging.target.com

2. Test for .git accessibility:
   curl -I https://staging.target.com/.git/
   → HTTP 200, directory listing accessible

3. Dump repository:
   git-dumper https://staging.target.com/.git/ /tmp/staging-git/

4. Analyze repository contents:
   cd /tmp/staging-git

   # Check for sensitive data in commits
   git log --all --source --remotes --full-history -- "*.env"
   → Found commit with .env file containing DB_PASSWORD=Secret123

   # Check for hardcoded credentials in code
   grep -r "password" --include="*.php" --include="*.js"
   → Found multiple instances of hardcoded passwords in config files

   # List files
   find . -name "*.sql" -o -name "*.conf" -o -name "*.env"
   → Multiple configuration files exposed

5. Document extracted information:
   - Database: host, username, password, database name
   - API keys: payment gateway, email service, SMS service
   - Source code: full application code accessible

## Impact
- Source code exposure: attacker bisa analyze code untuk find additional vulnerabilities
- Credential theft: database credentials bisa digunakan untuk direct database access
- API key abuse: third-party service credentials bisa misused
- Internal path exposure: internal network structure revealed
- Further attack: exposed information bisa digunakan untuk escalate attack
- Severity: High — multiple attack vectors opened from single vulnerability

## Evidence
[crt.sh JSON output showing staging.target.com subdomain]
[curl -I showing .git/ directory accessible]
[git-dumper output showing successful dump]
[screenshot: config file with database credentials]
[screenshot: .env file with API keys]
[commit history showing credential in message]

## Remediation / Recommendation
1. Immediately remove .git directory from web root:
   sudo rm -rf /var/www/staging/.git/

2. Configure web server to deny access to .git directory:
   Apache: <Directory ~ "\.git"> Require all denied </Directory>
   Nginx: location ~ /\.git { deny all; }

3. Rotate all exposed credentials:
   - Database password
   - API keys (payment gateway, email, SMS)
   - Any secrets found in exposed files

4. Audit all code for hardcoded credentials and remove:
   - Use environment variables
   - Use secret management solution (Vault, AWS Secrets Manager)

5. Implement regular security scanning untuk detect future exposure:
   - Automated scan for .git, .env, backup files
   - GitHub secret scanning untuk repositories

6. Add subdomain to scope and monitor for similar issues di other subdomains
```

---

*Module ini menjembatani fase recon dengan fase exploitation. Tanpa attack surface map yang baik, researcher akan hunting secara random dan miss target yang valuable. Invest waktu untuk mapping dengan benar — itu akan determine efisiensi dan effectiveness dari seluruh hunting session.*