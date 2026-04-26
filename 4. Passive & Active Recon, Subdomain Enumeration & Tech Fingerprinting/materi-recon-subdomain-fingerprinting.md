# Passive & Active Recon, Subdomain Enumeration & Tech Fingerprinting

## Fokus Materi

Menguasai teknik reconnaissance untuk memetakan attack surface target secara komprehensif. Dari passive recon (tanpa menyentuh target) sampai active recon (probe langsung), peserta akan membangun pipeline recon yang efisien dan mendapatkan gambaran lengkap asset target sebelum hunting dimulai.

## Deskripsi Materi

Bug bounty dimulai bukan saat pertama menemukan vulnerability — tapi saat pertama menemukan target. Reconnaissance adalah fase paling underestimate tapi paling impactful dalam bug bounty. Researcher yang langsung冲向漏洞 scanning tanpa memahami target akan mendapatkan noise, bukan signal.

Passive recon adalah pengumpulan informasi tentang target tanpa mengirim traffic apapun ke target secara langsung. Ini memanfaatkan data public yang sudah tersedia: search engine, certificate transparency log, DNS records, GitHub, Shodan, dan puluhan sumber lain. Passive recon tidak membuat target aware bahwa kamu sedang menginvestigasi mereka, dan tidak ada risk triggering detection.

Subdomain enumeration adalah inti dari passive recon. Organisasi modern menggunakan hundreds of subdomains untuk different services, environments, dan teams. Setiap subdomain adalah potential attack surface yang mungkin lebih vulnerable dari main domain. Subdomain yang di-forgot sering tidak mendapat security attention yang sama dengan main domain.

Active recon membawa kita ke level berikutnya: mengirim traffic langsung ke target untuk probe what's alive. Ini termasuk subdomain discovery via DNS brute force, HTTP probing untuk identify what's running, port scanning untuk menemukan services yang exposed, dan directory fuzzing untuk mapping endpoints.

Technology fingerprinting memungkinkan kita memahami apa yang berjalan di target. Dengan mengidentifikasi stack (Apache vs Nginx, PHP vs Node.js, WordPress vs custom CMS, React vs Angular), kita bisa focus pada vulnerability yang relevant untuk stack tersebut. Tools seperti Wappalyzer, WhatWeb, dan builtwith memberikan fingerprinting otomatis.

Pipeline recon yang baik automates workflow dari passive → active → fingerprinting, sehingga researcher bisa spend lebih banyak waktu pada exploitation daripada collection.

## Topik Pembahasan

• Passive recon sources: Google Dorking, Shodan, Censys, Fofa, crt.sh (Certificate Transparency), WHOIS, DNSdumpster, LeakIX
• Google Dorking: site:, inurl:, intitle:, filetype:, cache:, related: — untuk menemukan exposed data, backup, dan endpoint tersembunyi
• Certificate Transparency (CT) logs: crt.sh, Entrust, Google CRT — sumber utama subdomain enumeration
• GitHub recon: dorking untuk credential, API key, internal endpoint, sensitive configuration
• Wayback Machine: historical mapping, endpoint discovery, config file discovery
• Passive subdomain enumeration: subfinder, amass, assetfinder, findomain — comparison cara kerja dan output
• Active subdomain enumeration: DNS brute force (wordlist-based), DNS resolution, permutation
• httpx: probe subdomain sekaligus collect status code, title, tech stack, dan content-type dalam satu tool
• Nmap lightweight: port scan yang tidak alerting WAF — timing, port selection, dan service detection
• Directory & parameter fuzzing: ffuf, dirsearch, dan wordlist selection (SecLists, raft)
• Tech fingerprinting: Wappalyzer (browser), whatweb (CLI), builtwith (online), w9scan — kapan pakai mana
• WAF detection: wafw00f, manual via header anomaly detection
• Recon pipeline: bash scripting atau tools seperti Hexstrike untuk automate workflow end-to-end
• Organize hasil recon: format output (JSON/line-separated), tooling untuk parse dan visualize

## Tujuan Pembelajaran

Setelah sesi ini, peserta diharapkan mampu:
1. Melakukan passive recon secara comprehensive tanpa mengirim traffic ke target
2. Menggunakan minimal 5 passive recon sources untuk maximize asset discovery
3. Melakukan subdomain enumeration dengan tools otomatis dan manual
4. Melakukan active recon: DNS brute force, HTTP probing, port scanning
5. Melakukan technology fingerprinting dan stack identification
6. Membangun automated recon pipeline yang running end-to-end
7. Mengorganisir dan menganalisis hasil recon untuk attack surface mapping

## Real Case Bug Bounty Report

- Platform: HackerOne
- Program/Target: Program besar dengan bounty public disclosure
- Jenis vulnerability: Exposed .git directory via subdomain yang tidak diobservasi
- Link report: https://hackerone.com/reports/XXXXX (disclosed)
- Ringkasan kasus: Researcher melakukan subdomain enumeration terhadap target menggunakan subfinder + amass. Dari hasil CT logs, ditemukan subdomain `staging-api.target.com`. Researcher membuka subdomain tersebut dan menemukan .git directory accessible publicly. Dengan git-dumper, researcher mengekstrak source code lengkap yang mengandung database credentials dan internal API keys.
- Root cause: Server staging tidak memiliki proper access control. .git directory tidak di-exclude dari web root, dan subdomain tidak ada di main scope disclosure tapi tetap company-owned asset.
- Impact: Database credentials leak → potential RCE dan data breach. Severity: Critical.
- Pelajaran untuk bug hunter: Subdomain enumeration membuka door ke asset yang tidak mendapat security attention. Staging, dev, dan test subdomain sering lebih vulnerable daripada production.

---

- Platform: Bugcrowd
- Program/Target: SaaS company program
- Jenis vulnerability: GitHub dorking menemukan internal API documentation dan credentials
- Link report: Public writeup researcher's blog
- Ringkasan kasus: Researcher menggunakan GitHub dorking dengan query seperti `target.com api_key`, `target.com password`, `target.com secret`. Ditemukan beberapa repositories, salah satunya adalah internal project dengan AWS credentials di commit history. Researcher responsibly report, company revoke keys sebelum diexploited.
- Root cause: Developer commit sensitive data ke public repository. credentials tidak di-remove dari git history (masih ada di commit lama).
- Impact: Potential AWS account compromise jika keys active. Severity: Critical.
- Pelajaran untuk bug hunter: GitHub dorking adalah salah satu teknik recon paling valuable dan sering menemukan credential tanpa perlu touching target sama sekali.

## Analisis Teknis

### Passive Recon Deep Dive

#### Google Dorking Patterns

```
# Backup files yang exposed
site:target.com filetype:bak
site:target.com filetype:sql
site:target.com filetype:log

# Configuration files
site:target.com filetype:config
site:target.com filetype:ini
site:target.com filetype:yml

# Exposed documentation
site:target.com intitle:"index of" "admin"
site:target.com inurl:wp-content/uploads

# Internal tools exposed
site:target.com inurl:swagger
site:target.com inurl:api-docs
site:target.com inurl:debug

# Sensitive data
site:target.com filetype:xlsx "password"
site:target.com filetype:pdf "confidential"
```

#### Certificate Transparency Logs

CT logs adalah sumber subdomain terbesar yang available:

```
# crt.sh search
curl -s "https://crt.sh/?q=target.com&output=json" | jq '.[].name_value' | sort -u

# Contoh output:
target.com
www.target.com
api.target.com
staging.target.com
dev.target.com
k8s.prod.target.com
jenkins.internal.target.com
```

Kenapa ini powerful: Sertifikat yang di-issue untuk subdomain apapun akan appear di CT log, termasuk temporary atau internal subdomain yang companies tidak sadari publicly visible.

#### GitHub Recon Methodology

```
# Search for files from organization
repo:target-org-name OR owner:target-org-name sensitive

# Search for keywords in code
filename:config.php password
filename:.env DB_PASSWORD
filename:credentials.json api_key

# Search in commit history
git log --all -S "password" --oneline
git log --all -S "api_key" --oneline

# Tools
gitrob (now Gitleaks ecosystem)
trufflehog (scan for secrets di repo)
```

#### Shodan / Fofa / Censys

```
Shodan: organisasi punya exposed service dengan IP public
- Query: org:"Target Company Name"
- Query: hostname:target.com
- Query: product:"nginx" country:"ID"

Fofa (Shodan alternative untuk APAC):
- Query: domain="target.com"
- Query: host="*.target.com"
- Query: body="target.com" && country="ID"

Censys:
- Query: names: target.com
- Query: services.http.response.headers.location: target.com
```

### Subdomain Enumeration Methodology

#### Tools Comparison

| Tool | Method | Speed | Output | Best For |
|------|--------|-------|--------|----------|
| subfinder | Passive (30+ source API) | Fast | Domain list | Fast enumeration dari banyak source |
| amass | Passive + Active + OSINT | Slow | Domain list + source | Comprehensive dengan crawling |
| assetfinder | Passive (Amass + certspotter + more) | Fast | Domain list | Quick discovery |
| findomain | Passive (CRT + VirusTotal + more) | Fast | Domain list | Simple, fast |
| shuffleDns | Brute force + wordlist | Medium | Domain list | Active brute force |

#### Wordlist untuk Brute Force

```
# Small-general (quick)
cewl wordlist, top1000 subdomains

# Medium-general (balanced)
dnsgen wordlist, top10000 subdomains

# Large/Target-specific
Custom wordlist berdasarkan OSINT dari target
(department names, product names, datacentre codes)
```

#### DNS Resolution

Setelah enumerate subdomain, perlu di-resolve ke IP untuk tahu mana yang alive:

```bash
# httpx: probe + resolve sekaligus
subfinder -d target.com | httpx -silent -title -status-code -tech-detect

# massdns: fast DNS resolver
massdns -r resolvers.txt -t A -o json domains.txt
```

### Active Recon Patterns

#### Port Scanning yang Tidak Alerting

```bash
# Timing stealthy: -T2 atau -T1
# Syn scan (need root): -sS
# Scan hanya port umum: -p 80,443,8080,8443,22,3000,5000
nmap -sS -T2 -p 80,443,8080,8443,22,3000,5000 --open target.com

# HTTP service detection
nmap -sV -p 80,443,8080,8443 target.com

# Top 100 port
nmap -sS -T2 -F --open target.com
```

Kenapa stealth: Too aggressive scanning bisa trigger rate limit, WAF, atau automated security alert yang membuat target aware of your presence. Keep noise low.

#### Directory Fuzzing

```bash
# ffuf untuk directory discovery
ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt \
     -u https://target.com/FUZZ \
     -mc 200,204,301,302,307,401,403 \
     -fc 404 \
     -o results.json

# ffuf dengan recursion untuk nested directory
ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt \
     -u https://target.com/FUZZ \
     -recursion \
     -recursion-depth 2

# Specific extensions
ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt \
     -u https://target.com/FUZZ \
     -e .php,.html,.js,.txt,.bak,.env
```

#### Tech Fingerprinting Pipeline

```
Step 1: HTTP probe semua subdomain dengan httpx
   → Status code, title, tech stack, content-type

Step 2: Screenshots semua live subdomain dengan httpScreenshot atau eyewitness

Step 3: whatweb untuk detail tech fingerprint
   whatweb -a3 https://target.com

Step 4: Wappalyzer browser extension untuk interactive browsing

Step 5: Nuclei untuk vulnerability scanning berdasarkan tech fingerprint
```

### Recon Pipeline Architecture

```bash
#!/bin/bash
# Recon pipeline sederhana

TARGET="target.com"
OUTPUT_DIR="recon/$TARGET"

# Phase 1: Passive enumeration
echo "[*] Passive subdomain enumeration..."
subfinder -d $TARGET -o $OUTPUT_DIR/subdomains-passive.txt
amass enum -passive -d $TARGET -o $OUTPUT_DIR/subdomains-amass.txt
findomain -t $TARGET -u $OUTPUT_DIR/subdomains-findomain.txt

# Phase 2: Combine & dedupe
cat $OUTPUT_DIR/subdomains-*.txt | sort -u > $OUTPUT_DIR/all-subdomains.txt

# Phase 3: DNS resolution + HTTP probe
echo "[*] HTTP probing..."
cat $OUTPUT_DIR/all-subdomains.txt | httpx \
    -title -tech-detect -status-code \
    -o $OUTPUT_DIR/alive-subdomains.json

# Phase 4: Screenshot
echo "[*] Screenshots..."
cat $OUTPUT_DIR/all-subdomains.txt | httpx -silent | \
    eyewitness --web --timeout 30 -d $OUTPUT_DIR/screenshots/

# Phase 5: Directory fuzzing pada alive subdomain
echo "[*] Directory fuzzing..."
for url in $(cat $OUTPUT_DIR/alive-subdomains.txt | jq -r '.url'); do
    ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt \
         -u "$url/FUZZ" -o $OUTPUT_DIR/ffuf-$url.json
done
```

## Praktik Lab Legal

### Lab 1: Passive Recon Mastery

- **Nama lab:** Hidden Asset Discovery
- **Tujuan:** Menggunakan passive recon untuk memetakan semua asset target tanpa sending single packet ke target
- **Environment:** Kali Linux, browser, internet access
- **Langkah praktik:**

  1. Pilih target lab (misal: Juice Shop dijalankan locally atau target public yang disclosed untuk lab)
  2. Lakukan subdomain enumeration via crt.sh, subfinder, dan amass passive mode
  3. Gunakan Shodan untuk identifikasi exposed service
  4. Lakukan Google dorking untuk file sensitif: filetype:bak, filetype:log, filetype:env
  5. Cek Wayback Machine untuk historical endpoints
  6. Buat comprehensive asset list dalam spreadsheet
  7. Bandingkan hasil dari berbagai source — identifier overlap dan unique findings

- **Expected result:** Peserta membangun asset map yang comprehensive tanpa touching target secara aktif
- **Catatan keamanan:** Lab ini menggunakan teknik passive yang legal. Pastikan target yang di-test adalah authorized (lab lokal atau program bug bounty).

### Lab 2: Full Recon Pipeline

- **Nama lab:** End-to-End Recon
- **Tujuan:** Bangun automated pipeline dari subdomain enum sampai tech fingerprinting
- **Environment:** Kali Linux, tools recon sudah terinstall
- **Langkah praktik:**

  1. Buat script pipeline sesuai template di atas
  2. Run pipeline terhadap target lab
  3. Analyze output: alive subdomain, tech stack, potential vulnerable service
  4. Identifikasi subdomain dengan tech stack yang known vulnerable (misal: nginx lama, php versi lama)
  5. Buat prioritization: subdomain mana yang paling worth untuk deeper testing

- **Expected result:** Automated recon menghasilkan structured output yang siap untuk fase reconnaissance lanjutan
- **Catatan keamanan:** Untuk active scan, pastikan target adalah authorized. Gunakan lab lokal atau program dengan bug bounty yang mengijinkan scanning.

### Lab 3: GitHub Dorking for Secrets

- **Nama lab:** GitHub Intelligence
- **Tujuan:** Menggunakan GitHub search untuk menemukan credential dan sensitive data yang exposed
- **Environment:** Browser dengan GitHub access, gitrob/trufflehog CLI (optional)
- **Langkah praktik:**

  1. Identifikasi organization name dan developer username dari target
  2. Buat search query untuk target:
     - `target.com api_key`
     - `target.com password`
     - `target.com secret`
     - `filename:.env target`
     - `target.com jwt_secret`
  3. Analyze hasil yang relevant — check commit history
  4. Jika credentials ditemukan: document, responsible disclosure (report ke program, jangan exploit)
  5. Gunakan trufflehog untuk scan specific repositories yang ditemukan
  6. Buat inventory credential patterns yang ditemukan

- **Expected result:** Peserta memahami GitHub dorking methodology dan mampu menemukan exposed credentials jika ada
- **Catatan keamanan:** Jangan use credentials yang ditemukan untuk unauthorized access. Report segera ke program owner.

## Tools

- **Passive recon:** Google, Shodan, Censys, Fofa, crt.sh, DNSdumpster, LeakIX, Wayback Machine
- **Subdomain enum:** subfinder, amass, assetfinder, findomain, shuffleDNS, dnsx
- **HTTP probing:** httpx, naabu, masscan
- **Directory fuzzing:** ffuf, dirsearch, dirb, gobuster
- **Tech fingerprinting:** Wappalyzer, WhatWeb, BuiltWith, w9scan, nuclei
- **Screenshot:** eyewitness, httpx (screenshots), aquatone
- **Secrets scanning:** trufflehog, gitrob, gitleaks
- **Pipeline:** custom bash script, Hexstrike,ReconFTW

## Checklist Bug Hunter

- [ ] Gunakan minimal 3 passive recon source (CRT, Shodan, Google dorking)
- [ ] Lakukan subdomain enumeration dengan minimal 2 tools berbeda
- [ ] Resolve semua subdomain ke IP dan identify which are alive
- [ ] Lakukan tech fingerprinting pada semua live subdomain
- [ ] Screenshot semua interesting subdomain untuk visual inspection
- [ ] Lakukan directory fuzzing pada subdomain yang promising
- [ ] Search GitHub untuk target organization/developer credential
- [ ] Check Wayback Machine untuk historical endpoints
- [ ] Buat structured asset map (subdomain → tech → port → endpoint)
- [ ] Prioritize berdasarkan tech stack dan exposure untuk deeper testing

## Common Mistakes

1. **Hanya enumerasi subdomain tanpa resolve atau probe** — Menemukan 500 subdomain tidak berguna kalau tidak tahu mana yang alive. Always probe.

2. **Too aggressive active scanning** — Menggunakan nmap dengan timing -T4 atau masscan di rate tinggi bisa trigger automated security systems dan make target aware.

3. **Skip passive recon, langsung active** — Passive recon sering menemukan asset yang tidak akan kamu discover dengan scanning aktif. Keduanya penting.

4. **Tidak organizing hasil recon** — Tanpa structured output, akan sulit untuk tracking mana yang sudah di-test dan mana yang belum.

5. ** Hanya focus pada main domain** — Subdomain adalah low-hanging fruit yang sering contain vulnerable service yang diabaikan.

6. **Tidak menggunakan wordlist yang tepat** — Using default SecLists wordlist tanpa customization menghasilkan banyak false negative. Target-specific wordlist lebih efektif.

7. **Abaikan GitHub recon** — GitHub dorking bisa menemukan credential, source code, dan internal documentation tanpa perlu touching target sama sekali.

## Mitigasi Developer

- Monitor Certificate Transparency log untuk发现 unauthorized subdomain dengan company certificate
- Remove sensitive files (.git, .env, .bak, backup) dari web-accessible directory
- Don't commit credentials to GitHub (gunakan git-secrets, Gitleaks di CI/CD pipeline)
- Implementasi subdomain takeover prevention (remove DNS pointing ke deprecated service)
- Regularly audit exposed assets di Shodan/Censys
- Remove staging/dev environment dari public access atau protect dengan proper authentication
- Implementasi WAF/CDN dengan logging untuk detect recon activity

## Mini Quiz

1. Teknik passive recon yang memanfaatkan Certificate Transparency log berguna untuk:
   a) Scan port target secara stealth
   b) Menemukan subdomain yang di-register dengan certificate publik
   c) Crack password secara offline
   d) Intercept traffic target

2. Tool yang best digunakan untuk HTTP probing + tech fingerprinting sekaligus:
   a) nmap
   b) ffuf
   c) httpx
   d) masscan

3. GitHub dorking dengan query `filename:.env target.com` mencari:
   a) Semua file dari target.com organization
   b) File .env yang mengandung referensi ke target.com
   c) Repository milik target.com
   d) Commit message yang mengandung target.com

4. WAF detection bisa dilakukan dengan:
   a) Mengirim request berbahaya ke target
   b) Menganalisis header/response anomaly via tool seperti wafw00f
   c) Decrypt HTTPS traffic
   d) Scanning port secara terus-menerus

5. Pipeline recon yang efektif sebaiknya:
   a) Hanya menggunakan automated scanner
   b) Kombinasi passive → active → fingerprinting dengan hasil yang terstruktur
   c) Hanya focus pada brute force subdomain
   d) Dilakukan sekali saja di awal sebelum hunting

**Kunci Jawaban:** 1-B, 2-C, 3-B, 4-B, 5-B

## Assignment

1. **Recon to Find Subdomain Takeover:** Pilih target yang disclosed untuk lab. Lakukan full recon dan identifikasi subdomain yang bisa vulnerable untuk takeover (eligible DNS pointing ke service yang deprecated). Document process dan hasil.

2. **GitHub Dorking Report:** Lakukan GitHub dorking untuk organization yang kamu pilih. Buat laporan yang mencakup: keywords yang efektif, repositories yang ditemukan, dan apakah ada sensitive data yang discovered (document only, don't access).

3. **Build Automated Pipeline:** Buat bash script yang automate recon pipeline dari awal sampai akhir untuk target yang diberikan. Include: subdomain enum (passive + active), DNS resolution, HTTP probing, tech fingerprinting, directory fuzzing. Output harus structured (JSON/spreadsheet).

4. **Compare Passive Recon Sources:** Gunakan 5 passive recon source berbeda untuk target yang sama. Compare hasil: source mana yang memberikan most unique findings? Buat recommendation untuk priority order.

## Template Report Bug Bounty

```markdown
# Bug Report: Exposed Sensitive File via Unmonitored Subdomain

## Summary
Subdomain staging.target.com yang ditemukan dari Certificate Transparency log
mengandung exposed .git directory yang bisa di-dump untuk mendapatkan source
code dan credentials.

## Platform / Program
HackerOne | [Program Name]

## Severity
High | CVSS 8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

## Vulnerability Type
Information Disclosure / Sensitive Data Exposure

## Asset / Endpoint
http://staging.target.com/.git/

## Description
Passive reconnaissance menggunakan Certificate Transparency log (crt.sh)
menemukan subdomain staging.target.com yang tidak disclosed di program scope
publicly tapi merupakan asset legitimate milik company.

Saat mengakses subdomain tersebut, ditemukan:
1. .git directory accessible publicly
2. No authentication required
3. git-dumper bisa mengekstrak entire repository

Repository mengandung:
- Database credentials (username/password di config)
- Internal API keys
- Source code dengan hardcoded secrets

## Steps to Reproduce
1. Query crt.sh untuk target.com certificate
   curl "https://crt.sh/?q=target.com&output=json" | jq '.[].name_value'
   → Ditemukan staging.target.com

2. Browse ke http://staging.target.com/.git/
   → Directory listing accessible

3. Dump repository dengan git-dumper
   git-dumper http://staging.target.com/.git/ /tmp/staging-dump

4. Inspect repository
   cd /tmp/staging-dump
   git log --oneline
   git diff HEAD~5

   → Ditemukan credentials di config/database.php
   → Ditemukan API keys di .env file

## Impact
- Database credentials leak → potential database compromise
- API keys → bisa digunakan untuk unauthorized API access
- Source code → bisa reveal additional vulnerabilities
- Full compromise of staging environment

## Evidence
[CRT.sh JSON output showing staging.target.com]
[Screenshot: .git directory accessible]
[Screenshot: credentials found in source code]
[Har file: HTTP history showing directory listing]

## Remediation / Recommendation
1. Remove .git directory dari web root atau block access via web server config
2. Remove staging subdomain dari public internet atau protect dengan proper auth
3. Rotate all credentials yang found (database password, API keys)
4. Audit other subdomains untuk similar misconfiguration
5. Implementasi automated scanning untuk detect exposed .git di future
```

---

*Recon adalah phase paling penting. Invest waktu yang cukup di sini dan kamu akan menemukan target yang researcher lain miss. 80% dari hasil bug bounty yang besar berasal dari recon yang thorough.*