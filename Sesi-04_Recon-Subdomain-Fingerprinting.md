# Sesi 04 — Passive & Active Recon, Subdomain Enumeration & Tech Fingerprinting

> **Level:** Beginner–Intermediate  
> **Durasi Estimasi:** 4–5 jam (teori + praktik pipeline)  
> **Prasyarat:** Sesi 02 (HTTP Fundamentals)  
> **Tools:** subfinder, httpx, amass, ffuf, nmap, shodan, crt.sh, Wappalyzer, wafw00f

---

## 🎯 Tujuan Pembelajaran

Setelah menyelesaikan sesi ini, peserta mampu:
- Melakukan passive recon tanpa menyentuh target langsung
- Membangun pipeline subdomain enumeration otomatis
- Melakukan active recon secara bertanggung jawab dan dalam scope
- Mengidentifikasi tech stack, WAF, dan framework target
- Menghasilkan attack surface map yang actionable untuk fase exploitation

---

## 📚 Bagian 1 — Mindset Recon: Mengapa Ini Sesi Terpenting

Recon yang buruk = menemukan bug di tempat yang salah, atau bahkan out-of-scope.  
Recon yang baik = menemukan **subdomain tersembunyi yang jarang di-test** → lebih sedikit kompetitor → peluang bounty lebih tinggi.

```
Target: *.hackerone.com

Sebagian besar hunter test:
  - app.hackerone.com (ramai, banyak duplikat)

Hunter dengan recon baik temukan:
  - legacy-api.hackerone.com (sedikit yang test)
  - staging.hackerone.com (lebih sedikit proteksi)
  - internal-dashboard.hackerone.com (mungkin vulerable!)
```

> **Filosofi:** Semakin banyak attack surface yang kamu peta, semakin besar peluang menemukan endpoint yang belum pernah di-test siapapun.

---

## 📚 Bagian 2 — Passive Recon: Tanpa Menyentuh Target

### 2.1 Google Dorking (Google Hacking)

Google Dork adalah query khusus untuk mencari informasi sensitif yang ter-index oleh Google.

**Dork Penting untuk Bug Hunter:**

```bash
# Cari subdomain
site:*.target.com

# Cari halaman login
site:target.com inurl:login
site:target.com inurl:admin
site:target.com inurl:dashboard

# Cari file sensitif yang ter-index
site:target.com ext:env
site:target.com ext:config
site:target.com ext:sql
site:target.com ext:backup
site:target.com ext:log

# Cari error messages
site:target.com "Warning: mysql_"
site:target.com "ORA-" (Oracle error)
site:target.com "SQLSTATE["

# Cari exposed credentials
site:target.com "password" filetype:txt
site:target.com "api_key" filetype:json

# Exclude subdomain utama (temukan yang tersembunyi)
site:target.com -www -mail -ftp
```

**Referensi:**
- 🔗 [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database)
- 🔗 [Pentest Tools Dork Generator](https://pentest-tools.com/information-gathering/google-hacking)

### 2.2 Certificate Transparency Logs (crt.sh)

SSL/TLS certificate disimpan di public log (CT logs). Ini adalah sumber subdomain **paling reliable**.

```bash
# Manual via browser
https://crt.sh/?q=%.target.com

# Via command line
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
  jq -r '.[].name_value' | \
  sort -u | \
  grep -v '*'

# Output contoh:
# api.target.com
# staging.target.com
# internal.target.com
# legacy-v2.target.com
```

### 2.3 Shodan: Search Engine untuk Internet-Connected Devices

```bash
# Install Shodan CLI
pip install shodan
shodan init [API_KEY]

# Query dasar
shodan search "org:target.com"
shodan search "hostname:target.com"
shodan search "ssl:target.com"

# Temukan service tersembunyi
shodan search "hostname:target.com port:8080"
shodan search "hostname:target.com http.title:admin"

# Via browser: https://www.shodan.io/
# Query: org:"Company Name" country:ID
```

> 💡 **Pro Tip:** Shodan sering menampilkan port non-standard yang tidak ditest hunter lain (8443, 8888, 9090, dll).

### 2.4 WHOIS & DNS/ASN Enumeration

```bash
# WHOIS — cari info registrant, nameserver
whois target.com

# DNS records — cari semua record
dig target.com ANY
dig target.com MX
dig target.com TXT    # sering ada API key atau verification token!
dig target.com SPF

# Contoh TXT record yang menarik:
# v=spf1 include:mailgun.org include:sendgrid.net ~all
# → target pakai Mailgun & Sendgrid = bisa uji email-related bugs

# ASN lookup — cari range IP yang dimiliki target
curl -s "https://api.bgpview.io/search?query_term=target.com" | jq
# Setelah dapat ASN:
whois -h whois.radb.net -- '-i origin AS12345' | grep -Eo "([0-9.]+){4}/[0-9]+"
```

### 2.5 GitHub Dorking: Cari Credential & Endpoint yang Ter-leak

GitHub adalah salah satu sumber **most valuable** dalam recon. Developer sering tidak sengaja commit secret.

```bash
# Search di GitHub.com:
"target.com" password
"target.com" api_key
"target.com" secret
"@target.com" password
"target.com" token
filename:.env "target.com"
filename:config.js "target.com"
filename:database.yml "target.com"
```

**Tools untuk GitHub Recon:**
```bash
# trufflehog — scan git history untuk secret
trufflehog git https://github.com/target/repo

# gitleaks — cari credentials di repo
gitleaks detect --source /path/to/repo -v

# gitrob (web-based)
# https://github.com/michenriksen/gitrob
```

> **⚠️ Etika:** Hanya scan repository yang dimiliki oleh target (sesuai scope). Jangan scan repo developer individual kecuali jelas terkait perusahaan target.

### 2.6 Wayback Machine: Endpoint yang Sudah Dihapus

Endpoint yang "dihapus" dari aplikasi sering masih ter-crawl oleh Wayback Machine.

```bash
# Manual
https://web.archive.org/web/*/target.com/*

# Via command line dengan waybackurls
go install github.com/tomnomnom/waybackurls@latest
echo "target.com" | waybackurls | tee wayback_output.txt

# Filter endpoint menarik
cat wayback_output.txt | grep -E "\.(php|asp|aspx|jsp)$"
cat wayback_output.txt | grep -E "api|admin|debug|backup"
cat wayback_output.txt | grep "?"  # URL dengan parameter
```

---

## 📚 Bagian 3 — Active Recon: Langsung ke Target

> **⚠️ Penting:** Active recon langsung mengirim request ke server target. Pastikan target ada dalam scope program bug bounty sebelum memulai.

### 3.1 Subdomain Enumeration Aktif

#### subfinder — Passive + Active Enum

```bash
# Install
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Basic usage
subfinder -d target.com

# Dengan API keys (lebih banyak hasil)
subfinder -d target.com -all -recursive

# Output ke file
subfinder -d target.com -o subdomains.txt

# Multiple targets
subfinder -dL domains.txt -o subdomains.txt
```

#### amass — Comprehensive OSINT

```bash
# Install
go install -v github.com/owasp-amass/amass/v4/...@master

# Passive (tanpa query langsung ke target)
amass enum -passive -d target.com

# Active (DNS brute force + passive)
amass enum -active -d target.com -o amass_results.txt

# Intel mode — cari semua domain terkait organisasi
amass intel -org "Target Company Name"
```

#### assetfinder — Cepat & Ringan

```bash
go install github.com/tomnomnom/assetfinder@latest
assetfinder --subs-only target.com
```

#### Gabungkan Semua Hasil

```bash
# Jalankan semua tools, gabung, dan deduplicate
subfinder -d target.com -silent >> all_subdomains.txt
amass enum -passive -d target.com -o amass.txt && cat amass.txt >> all_subdomains.txt
assetfinder --subs-only target.com >> all_subdomains.txt
cat crt_sh_results.txt >> all_subdomains.txt

# Deduplicate
sort -u all_subdomains.txt > unique_subdomains.txt
echo "Total unique subdomains: $(wc -l < unique_subdomains.txt)"
```

### 3.2 httpx: Probe Subdomain yang Live

Setelah punya list subdomain, perlu tahu mana yang **aktif dan accessible**.

```bash
# Install
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Basic probe
cat unique_subdomains.txt | httpx

# Dengan info lengkap
cat unique_subdomains.txt | httpx \
  -status-code \
  -title \
  -tech-detect \
  -web-server \
  -content-length \
  -o live_hosts.txt

# Output contoh:
# https://api.target.com [200] [API Gateway] [nginx] [API v2.0] [1234]
# https://staging.target.com [200] [Staging Dashboard] [Apache] [React] [8901]
# https://legacy.target.com [301] → https://www.target.com
# https://internal.target.com [401] [Employee Portal] [IIS]
```

> 🎯 **Focus:** Subdomain dengan status 401 (ada sesuatu tapi perlu auth) dan subdomain dengan title unik sering menjadi target paling menarik.

### 3.3 Nmap: Port Scanning

```bash
# Scan port web umum — ringan, tidak alerting
nmap -p 80,443,8080,8443,8000,8888,3000,4000,9090 \
     --open \
     -T3 \
     -oN nmap_results.txt \
     [IP_TARGET]

# Scan dari list subdomain (setelah resolve IP)
nmap -p 80,443,8080,8443 \
     --open \
     -iL ip_list.txt \
     -oN nmap_web_ports.txt

# Service version detection (lebih noisy)
nmap -sV -p 80,443,8080,8443 [TARGET] -oN nmap_service.txt
```

### 3.4 Directory & Parameter Fuzzing dengan ffuf

```bash
# Install
go install github.com/ffuf/ffuf/v2@latest

# Directory fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
     -u https://target.com/FUZZ \
     -mc 200,201,301,302,401,403 \
     -o ffuf_dirs.json

# Extension fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
     -u https://target.com/FUZZ \
     -e .php,.asp,.aspx,.jsp,.bak,.old,.txt,.json,.xml,.config,.env \
     -mc 200,201,301,302 \
     -o ffuf_files.json

# API endpoint fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -u https://api.target.com/api/v1/FUZZ \
     -mc 200,201,401,403 \
     -H "Content-Type: application/json"

# Wordlist tambahan yang direkomendasikan
# https://github.com/danielmiessler/SecLists
```

---

## 📚 Bagian 4 — Tech Fingerprinting & WAF Detection

### 4.1 Wappalyzer: Identifikasi Tech Stack

```bash
# Install sebagai browser extension
# https://www.wappalyzer.com/apps/

# Atau via CLI
npm install -g wappalyzer
wappalyzer https://target.com --pretty

# Output contoh:
# CMS: WordPress 6.4
# JavaScript Framework: React 18.2
# Web Server: nginx 1.18
# CDN: Cloudflare
# Analytics: Google Analytics
```

**Mengapa ini penting?**
```
WordPress → cek /wp-admin/, xmlrpc.php, plugin vulnerabilities
React SPA → focus ke API, client-side vulns
nginx → cek path traversal aliases, off-by-slash bugs
Cloudflare → WAF ada, cari bypass atau subdomain langsung ke origin
```

### 4.2 whatweb & builtwith

```bash
# whatweb — detail fingerprinting
whatweb https://target.com -v

# builtwith — via browser
# https://builtwith.com/target.com
```

### 4.3 WAF Detection

```bash
# wafw00f
pip install wafw00f
wafw00f https://target.com

# Output contoh:
# [*] Checking https://target.com
# [+] The site https://target.com is behind Cloudflare (Cloudflare Inc.)
```

**WAF Bypass Tips (untuk testing):**

```http
# Tambah header untuk bypass WAF rate limit
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1

# Case variation untuk bypass WAF rules
/aDmIn/ bukan /admin/
/admin/../admin/ (path normalization)

# Encoding
%61%64%6d%69%6e (URL encoding dari "admin")
```

---

## 📚 Bagian 5 — Membangun Recon Pipeline

### 5.1 Script Recon Otomatis Sederhana

```bash
#!/bin/bash
# recon_pipeline.sh
# Usage: ./recon_pipeline.sh target.com

TARGET=$1
OUTPUT_DIR="recon_${TARGET}_$(date +%Y%m%d)"
mkdir -p $OUTPUT_DIR

echo "[*] Starting recon for: $TARGET"
echo "[*] Output directory: $OUTPUT_DIR"

# 1. Passive subdomain enum
echo "[+] Running subfinder..."
subfinder -d $TARGET -silent -o $OUTPUT_DIR/subfinder.txt

echo "[+] Running assetfinder..."
assetfinder --subs-only $TARGET > $OUTPUT_DIR/assetfinder.txt

echo "[+] Querying crt.sh..."
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" | \
  jq -r '.[].name_value' | sort -u | grep -v '*' > $OUTPUT_DIR/crtsh.txt

# 2. Combine & deduplicate
cat $OUTPUT_DIR/subfinder.txt \
    $OUTPUT_DIR/assetfinder.txt \
    $OUTPUT_DIR/crtsh.txt | sort -u > $OUTPUT_DIR/all_subdomains.txt

echo "[+] Total unique subdomains: $(wc -l < $OUTPUT_DIR/all_subdomains.txt)"

# 3. Probe live hosts
echo "[+] Probing live hosts with httpx..."
cat $OUTPUT_DIR/all_subdomains.txt | \
  httpx -status-code -title -tech-detect -silent \
  -o $OUTPUT_DIR/live_hosts.txt

echo "[+] Live hosts: $(wc -l < $OUTPUT_DIR/live_hosts.txt)"

# 4. Quick port scan on live hosts
echo "[+] Port scanning..."
cat $OUTPUT_DIR/live_hosts.txt | \
  grep -oP 'https?://\K[^/\[]+' | sort -u > $OUTPUT_DIR/hostnames.txt

# 5. Summary
echo ""
echo "=== RECON SUMMARY ==="
echo "Total subdomains found  : $(wc -l < $OUTPUT_DIR/all_subdomains.txt)"
echo "Live hosts              : $(wc -l < $OUTPUT_DIR/live_hosts.txt)"
echo "Output directory        : $OUTPUT_DIR/"
echo "======================"
```

---

## 🔴 Real Bug Bounty Cases

### Case 1 — Subdomain Takeover via Unclaimed DNS

> **Platform:** HackerOne Public Reports  
> **Referensi Pola:** [HackerOne Subdomain Takeover Reports](https://hackerone.com/reports/examples)  
> **Severity:** High (P2)

**Skenario:**
Peneliti menjalankan subdomain enumeration pada target dan menemukan `staging.target.com` mengarah ke layanan pihak ketiga (misal: Heroku, GitHub Pages, AWS S3) yang **sudah tidak aktif/diklaim**.

```bash
# Discover subdomain
subfinder -d target.com | grep staging
# Output: staging.target.com

# Cek DNS
dig staging.target.com CNAME
# Output: staging.target.com. CNAME target-old-app.herokuapp.com.

# Cek apakah Heroku app masih exist
curl -I https://target-old-app.herokuapp.com
# HTTP/1.1 404 No such app  ← VULNERABLE!
```

**Exploit:** Attacker bisa klaim `target-old-app.herokuapp.com` dan deploy app sendiri → setiap user yang akses `staging.target.com` akan diarahkan ke app attacker → Phishing, Cookie Theft via `document.domain`.

**Fix:** Hapus DNS record yang mengarah ke layanan eksternal yang tidak aktif.

---

### Case 2 — Exposed .git Repository

> **Tipe:** Information Disclosure via Git Exposure  
> **Real Case Referensi:** Pola dari berbagai public HackerOne reports  
> **Severity:** High–Critical (P1–P2)

**Discovery:**
```bash
# ffuf menemukan /.git/ accessible
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -u https://target.com/FUZZ \
     -mc 200,301,403

# Output:
# /.git/ [301] ← FOUND!
```

**Exploitation:**
```bash
# Download git repository
git-dumper https://target.com/.git/ ./dumped_repo

# Lihat isi repository
cd dumped_repo
git log --oneline
git show HEAD
grep -r "password\|api_key\|secret\|token" .
```

**Temuan dalam kode:**
```python
# config.py (dari git dump)
DATABASE_URL = "postgresql://admin:SuperSecret123@db.internal:5432/prod"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_SECRET_KEY = "sk_live_..."
```

**Fix:** Tambahkan `/.git/` ke `.htaccess` deny rules, atau gunakan [gitignore dari GitHub](https://github.com/github/gitignore).

---

### Case 3 — S3 Bucket Public Listing (via Recon)

> **Referensi:** AWS S3 Bucket Misconfiguration — Pola umum di bug bounty  
> **Severity:** Medium–High tergantung konten

**Discovery melalui recon:**
```bash
# Temukan dari subdomain enum
assets.target.com → CNAME → target-assets.s3.amazonaws.com

# Atau dari wayback machine
cat wayback_output.txt | grep "s3.amazonaws.com"

# Test bucket listing
curl https://target-assets.s3.amazonaws.com/
# Jika rentan, XML listing akan muncul

# Atau menggunakan AWS CLI
aws s3 ls s3://target-assets --no-sign-request
```

**Dampak:** File backup, dokumen internal, data user, deployment scripts dengan credential.

---

## 🛠️ Lab Praktik

### Lab 1 — Bug Bounty Reconnaissance (TryHackMe)
- 🔗 [TryHackMe — Passive Reconnaissance](https://tryhackme.com/room/passiverecon)
- 🔗 [TryHackMe — Active Reconnaissance](https://tryhackme.com/room/activerecon)
- 🔗 [TryHackMe — Subdomain Enumeration](https://tryhackme.com/room/subdomainenumeration)

### Lab 2 — HackTheBox Academy
- 🔗 [Information Gathering - Web Edition](https://academy.hackthebox.com/module/details/144)
- 🔗 [Footprinting Module](https://academy.hackthebox.com/module/details/112)

### Lab 3 — PortSwigger
- 🔗 [Finding Hidden Functionality](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings)

### Lab 4 — Praktik Mandiri (Legal Targets)
- `*.wikipedia.org` — Open scope recon practice
- Bug Bounty programs dengan scope `*.domain.com` di HackerOne/Bugcrowd
- 🔗 [HackenProof Programs](https://hackenproof.com/programs)

---

## 📋 Recon Checklist per Target

```markdown
## Recon Checklist — [TARGET.COM]

### Passive Recon
- [ ] Google dorking (site:, inurl:, filetype:)
- [ ] crt.sh certificate transparency
- [ ] Shodan/Censys/Fofa query
- [ ] GitHub dorking (credentials, endpoints)
- [ ] WHOIS & DNS (MX, TXT, CNAME)
- [ ] Wayback Machine (old endpoints)

### Subdomain Enumeration
- [ ] subfinder
- [ ] amass (passive)
- [ ] assetfinder
- [ ] Combine & deduplicate

### Active Probing
- [ ] httpx (live host, title, tech stack)
- [ ] Nmap (non-standard ports)
- [ ] ffuf (directories, API endpoints)
- [ ] WAF detection (wafw00f)

### Tech Fingerprinting
- [ ] Framework/CMS identified
- [ ] Third-party services identified
- [ ] CDN identified
- [ ] Version numbers noted

### Quick Win Checks
- [ ] /.git/ accessible?
- [ ] /.env accessible?
- [ ] /backup/ accessible?
- [ ] Subdomain takeover potential?
- [ ] S3 bucket public?
```

---

## 📖 Referensi & Bacaan Lanjutan

| Sumber | Link | Topik |
|--------|------|-------|
| OWASP Testing Guide | [OTG-INFO](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/) | Information Gathering |
| Nahamsec | [Recon Playlist YouTube](https://www.youtube.com/c/nahamsec) | Bug Bounty Recon |
| Jason Haddix | [The Bug Hunter's Methodology](https://github.com/jhaddix/tbhm) | Full methodology |
| SecLists | [github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) | Wordlists |
| ProjectDiscovery | [chaos.projectdiscovery.io](https://chaos.projectdiscovery.io/) | Subdomain datasets |
| Subdomain Takeover | [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) | Takeover checker |

---

## 🔑 Key Takeaways

1. **Recon = Competitive Advantage** — Hunter yang recon lebih dalam temukan lebih banyak unique bugs
2. **Passive dulu, active kemudian** — Hindari meninggalkan traces di log sebelum yakin target in-scope
3. **Subdomain tersembunyi = attack surface paling berharga** — Sering less-protected daripada domain utama
4. **Tech fingerprinting mengarahkan testing** — Tahu stack = tahu vulnerability yang relevan
5. **Dokumentasikan semua** — Recon yang tidak terdokumentasi = effort yang terbuang

---

*Sesi berikutnya: **Sesi 07 — IDOR, BOLA & Broken Access Control***
