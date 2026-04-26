# Bug Bounty Ecosystem, Legal & Lab Setup

## Fokus Materi

Memahami ekosistem bug bounty secara menyeluruh — mulai dari cara kerja platform, aturan legal, sampai setup environment yang siap hunting. Bagian ini menjadi fondasi agar peserta bisa memulai perjalanan bug bounty dengan aman, terstruktur, dan efektif.

## Deskripsi Materi

Bug bounty adalah program rewards yang ditawarkan perusahaan/organisasi kepada researcher yang menemukan dan melaporkan kerentanan keamanan di sistem mereka. Berbeda dengan penetration test konvensional yang bersifat kontrak berbayar dan terjadwal, bug bounty bersifat open-ended: siapa saja bisa participate selama mengikuti aturan program.

Ekosistem bug bounty moderno didukung oleh platform-platform besar seperti HackerOne, Bugcrowd, Intigriti, dan YesWeHack. Masing-masing punya karakter, database program, dan mekanisme pembayaran yang berbeda. Researcher pemula sering terperangkap di memilih platform atau tidak memahami scope dengan benar — yang berujung pada waktu terbuang atau bahkan masalah legal.

Bagian legal adalah yang paling sering diremehkan. Banyak researcher baru yang tidak sadar bahwa menguji target tanpa izin yang jelas bisa berujung pada masalah hukum, bahkan jika niatnya "hanya untuk belajar." Di Indonesia sendiri, UU ITE No. 19 Tahun 2016 dan perubahannya mengatur tentang akses ilegal ke sistem komputer. safe harbor clause yang diterapkan platform bug bounty memberikan perlindungan terbatas, tapi bukan berarti membebaskan researcher dari tanggung jawab.

Setup environment yang benar adalah langkah konkret pertama. Tanpa environment yang tepat, peserta tidak akan bisa mengikuti materi sesi berikutnya. Kali Linux sebagai distro standar keamanan, Burp Suite sebagai proxy interceptor, dan tooling recon dasar harus sudah terinstall dan terkonfigurasi sebelum sesi berlangsung.

## Topik Pembahasan

• Definisi bug bounty: perbedaan mendasar dengan pentest,VDP (Vulnerability Disclosure Program), dan offensive security kontrak
• Mekanisme platform: cara kerja program, scope, bounty range, response time SLA
• Perbandingan platform utama: HackerOne, Bugcrowd, Intigriti, YesWeHack — fitur unik, tipo program, dan base researcher
• Memahami scope dengan benar: in-scope vs out-of-scope, asset identification, excluded vulnerability type
• Rules of engagement: apa yang boleh dan tidak boleh,禁止 aktivitas yang melanggar ToS
• Legal framework: safe harbor clause, UU ITE di Indonesia, case study disclosure yang bermasalah
• Setup Kali Linux: instalasi VM (VirtualBox/VMware), konfigurasi dasar, packages wajib
• Setup Burp Suite: instalasi,导入CA certificate ke browser, konfigurasi FoxyProxy
• Tooling recon dasar: daftar tools yang harus dikuasai di sesi awal (subfinder, httpx, ffuf, nmap, amass)
• Workflow dokumentasi: kenapa Obsidian/Notion/spreadsheet penting untuk tracking target, findings, dan report
• Mindset hunting: pendekatan sistematis vs. random approach, waktu management, kapan pivot target

## Tujuan Pembelajaran

Setelah sesi ini, peserta diharapkan mampu:
1. Memahami perbedaan bug bounty, pentest, dan VDP
2. Mengidentifikasi platform yang cocok untuk profile hunting masing-masing
3. Membaca dan menginterpretasi program scope dengan benar
4. Mengenali batasan legal dan safe harbor yang berlaku
5. Menginstal dan mengkonfigurasi Kali Linux + Burp Suite dengan benar
6. Menggunakan minimal 5 tooling recon dasar
7. Menyusun workflow dokumentasi untuk tracking proses hunting

## Real Case Bug Bounty Report

- Platform: HackerOne
- Program/Target: Shopify (Private program via invite)
- Jenis vulnerability: Information Disclosure via exposed Git repository
- Link report: Tidak bisa dipublikasikan (private invite), referensi dari writeup researcher di Hacktivity
- Ringkasan kasus: Researcher menemukan .git exposed di subdomain production Shopify via crawling. Dengan menggunakan git-dumper, researcher mengekstrak beberapa commit yang berisi credentials dan internal configuration.credential tersebut tidak lagi aktif, tapi ditemukan exposure data customer yang tidak terenkripsi.
- Root cause: Server misconfiguration yang mengijinkan directory listing pada folder .git, ditambah tidak ada rule firewall yang memblokir akses ke .git/config
- Impact: Kompromi potential terhadap internal sistem dan eksposur data konfigurasi sensitif. Severity: High (CVSS 8.2)
- Pelajaran untuk bug hunter: Recon phase yang thorough selalu menemukan .git/.env exposed. Ini bukan vulnerability canggih, tapi sering muncul dan nilainya signifikan.

---

- Platform: Bugcrowd
- Program/Target: Program publik dengan scope API dan web app
- Jenis vulnerability: Testing di luar scope (port scanning terhadap IP internal yang tidak disclosed)
- Link report: N/A (case disclosure dari triager response)
- Ringkasan kasus: Researcher melakukan Nmap scan ke seluruh range IP yang diasumsikan milik target.ternyata sebagian IP adalah shared infrastructure milik cloud provider lain. Researcher menerima warning dari platform dan program dihentikan sementara.
- Root cause: Researcher tidak memverifikasi kepemilikan asset secara resmi sebelum melakukan active recon
- Impact: Tidak ada impact keamanan aktual, tapi researcher masuk blacklist program dan mendapat warning formal dari platform
- Pelajaran untuk bug hunter: Selalu gunakan asset list yang disclosed di program scope. Jangan mengasumsikan atau extrapolate dari hasil DNS enumeration.

## Analisis Teknis

### Mekanisme Bug Bounty Platform

Platform bug bounty bekerja sebagai intermediary antara organization (program owner) dan researcher. Alurnya:

```
Organization membuat program
       ↓
Platform memvalidasi dan publish program
       ↓
Researcher join program, baca scope
       ↓
Researcher melakukan testing dalam scope
       ↓
Researcher Submit report via platform
       ↓
Triager/reviewer tangani report
       ↓
Severity assigned, bounty offered
       ↓
Researcher accept/negotiate/dispute
       ↓
Bounty paid, report disclosed
```

Scope adalah dokumen legal yang menentukan:
- Asset mana yang boleh ditest (domain, mobile app, API endpoint)
- Jenis vulnerability yang masuk (auth, injection, dll)
- Aktivitas yang dilarang (DoS fisik, automated scanning masif, social engineering)
- Bounty range per severity

### Legal Framework di Indonesia

UU ITE (Undang-Undang Informasi dan Transaksi Elektronik) mengatur tentang akses ilegal ke sistem komputer. Poin penting:

- Akses tanpa izin ke sistem yang bukan milik sendiri bisa dijerat Pasal 30 UU ITE
- Bug bounty platform menyediakan safe harbor clause yang melindungi researcher yang mengikuti rules
- Safe harbor TIDAK melindungi researcher yang melakukan testing di luar scope
- Beberapa kasus internasional menunjukkan researcher yang nekat testing tanpa izin menghadapi masalah hukum serius

Best practice legal:
1. Selalu test dalam scope program
2. Document semua aktivitas testing
3. Jangan pernah menyimpan atau mengeksfiltrasi data sensitif dari target
4. Jika menemukan data sensitif secara tidak sengaja, langsung report dan hapus

### Environment Setup untuk Bug Bounty

#### Kali Linux Installation

Kali Linux bisa dijalankan sebagai:
- Native install (untuk hardware dedicated)
- Virtual Machine (VirtualBox/VMware) — direkomendasikan untuk pemula
- WSL2 di Windows (limitasi pada beberapa tools jaringan)

Setup dasar setelah instalasi:
```bash
# Update sistem
sudo apt update && sudo apt upgrade -y

# Install tools recon dasar via Kali default
sudo apt install nmap masscan git curl wget

# Install Go (dibutuhkan banyak tools modern)
wget https://go.dev/dl/go1.21.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
```

#### Burp Suite Setup

1. Download Burp Suite Community/Professional dari PortSwigger
2. Konfigurasi browser dengan FoxyProxy extension:
   - Add proxy: 127.0.0.1:8080
   - Aktifkan hanya untuk target testing
3. Import Burp CA Certificate:
   - Buka Burp → Proxy → Import/export CA certificate
   - Install ke browser (Firefox direkomendasikan untuk testing)
   - Set browser proxy ke Burp, visit http://burpcert untuk download cert

#### Essential Tooling

```bash
# Subdomain enumeration
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# HTTP probe & fingerprinting
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Fast content discovery
go install github.com/ffuf/ffuf@latest

# Asset enumeration
go install github.com/tomnomnom/amass@latest

# Wordlists
git clone https://github.com/danielmiessler/SecLists.git ~/SecLists
```

#### Documentation Workflow

Tools yang direkomendasikan:
- **Obsidian** (gratis, offline-first, markdown native) — untuk notes harian researcher
- **Notion** (cloud-sync, kolaboratif) — untuk tracking program dan team
- **Spreadsheet** (Google Sheets/Excel) — untuk tracking target dan findings terstruktur

Template tracking minimal:
| Tanggal | Program | Target/Asset | Aktivitas | Finding | Status | Notes |
|---------|---------|--------------|----------|---------|--------|-------|
| 2026-01-15 | Shopify | shopify.com | Subdomain enum | subdomain.shopify.com | Pending | git exposed |

## Praktik Lab Legal

### Lab 1: Setup Environment Bug Bounty

- **Nama lab:** First Blood — Environment Setup
- **Tujuan:** Memastikan environment hunting siap digunakan untuk sesi selanjutnya
- **Environment:** VM Kali Linux (VirtualBox), akses internet
- **Langkah praktik:**

  1. Install Kali Linux di VirtualBox dengan spesifikasi minimal: 4GB RAM, 2 CPU, 50GB disk
  2. Konfigurasi network adapter ke "Bridged Adapter" agar dapat akses internet dengan IP sendiri
  3. Update sistem: `sudo apt update && sudo apt upgrade -y`
  4. Install Go dan set GOPATH
  5. Install tools recon: subfinder, httpx, ffuf, amass
  6. Install Burp Suite dan configure FoxyProxy di Firefox
  7. Import Burp CA certificate ke browser
  8. Verifikasi Burp intercept dengan visit http://burp → klik "CA Certificate" untuk download
  9. Install Obsidian dan buat vault baru "BugBounty-Notes"
  10. Buat folder structure: `Daily-Notes/`, `Programs/`, `Findings/`, `Reports/`

- **Expected result:** Peserta bisa intercept HTTP request dari browser melalui Burp, tools recon bisa jalan tanpa error, dan Obsidian vault sudah siap digunakan
- **Catatan keamanan:** Semua tools yang diinstall hanya digunakan untuk testing di target yang memiliki authorization. Jangan pernah menggunakan tools ini di target di luar scope tanpa izin.

### Lab 2: Platform Exploration

- **Nama lab:** Platform Reconnaissance
- **Tujuan:** Mengenali interface platform bug bounty dan memahami cara baca program scope
- **Environment:** Browser, akun di platform bug bounty (minimal HackerOne atau Bugcrowd, akun gratis sudah cukup)
- **Langkah praktik:**

  1. Buat akun di HackerOne (gratis) dan explore 3 program publik
  2. Untuk setiap program, identifikasi:
     - Scope (domain, subdomain, mobile app yang masuk)
     - Out-of-scope (apa yang dilarang)
     - Bounty range (min-max per severity)
     - Rules of engagement
  3. Identifikasi program yang memiliki VDP (hanya disclosure, tanpa bounty) sebagai latihan scope reading
  4. Buat comparison sheet: ketiga platform dari sudut pandang researcher
  5. Subscribe ke newsletter/HackerOne digest untuk memahami trending vulnerability type

- **Expected result:** Peserta paham cara baca scope dengan benar dan bisa membedakan program yang layak difokuskan vs. yang tidak
- **Catatan keamanan:** Ini adalah aktivitas read-only yang legal di platform publik. Tidak ada testing aktif yang dilakukan.

## Tools

- **OS/Distro:** Kali Linux (VM/instalasi native)
- **Proxy:** Burp Suite Community/Professional
- **Browser extension:** FoxyProxy Standard, Wappalyzer
- **Recon tools:** subfinder, amass, httpx, ffuf, nmap, masscan
- **Documentation:** Obsidian, Notion, atau spreadsheet
- **Platform belajar:** HackerOne Hacktivity, Bugcrowd Directory, Intigriti Disclosure

## Checklist Bug Hunter

- [ ] Akun platform sudah dibuat dan verified (HackerOne, Bugcrowd, Intigriti minimal)
- [ ] Kali Linux sudah terinstall dan running dengan benar
- [ ] Burp Suite sudah terinstall, CA certificate sudah diimport ke browser
- [ ] FoxyProxy sudah dikonfigurasi untuk intercept traffic
- [ ] Go environment sudah ter-set dan tools recon sudah terinstall
- [ ] SecLists dan wordlist sudah tersedia di sistem
- [ ] Obsidian/Notion sudah di-setup dengan folder structure
- [ ] Scope mindestens 1 program sudah dibaca dan dipahami
- [ ] Legal boundary sudah dipahami (UU ITE + platform safe harbor)
- [ ] Workflow dokumentasi sudah dirancang dan siap dijalankan

## Common Mistakes

1. **Testing di luar scope** — Researcher baru sering tidak sabar dan langsung scan semua IP yang diasumsikan milik target. Ini adalah fastest way untuk masuk blacklist atau masalah legal.

2. **Tidak baca rules of engagement** — Beberapa program melarang automated scanning di atas threshold request per detik tertentu. Melanggar ini bisa cause account suspension.

3. **Tidak document aktivitas** — Tanpa catatan, sulit untuk prove impact atau menjawab pertanyaan triager. Ini sering membuat report di-reject.

4. **Skip recon, langsung exploitation** — Researcher yang tidak sabar langsung冲向 vulnerability scanning tanpa memahami attack surface target. Hasil: banyak false positive, miss target sebenarnya.

5. **Terlalu fokus pada automated scanner** — Banyak vulnerability yang hanya terdeteksi lewat pendekatan manual dan understanding bisnis logic target.

6. **Menggunakan tools tanpa tuning** — ffuf dengan default wordlist dan thread tinggi akan trigger rate limit atau WAF dalam hitungan menit. Tuning diperlukan untuk setiap target.

7. **Abaikan documentation workflow** — Researcher yang tidak punya sistem untuk tracking target akan spending waktu untuk hal yang sama berulang-ulang.

## Mitigasi Developer

Dari sisi developer dan tim keamanan organization:

- Publish program bug bounty yang jelas dengan scope yang ter-definisikan dengan baik
- Gunakan clear asset identification — bukan wildcard yang terlalu luas
- Implementasikan rate limiting dan anomaly detection di sisi server
- Pastikan safe harbor clause mencakup aktivitas yang reasonable dan tidak malicious
- Respond ke report dalam SLA yang dijanjikan (biasanya 7-14 hari untuk first response)
- Dokumentasikan semua communication dengan researcher
- Jangan melakukan legal threat ke researcher yang beriktikad baik (good faith researcher)

## Mini Quiz

1. Apa perbedaan fundamental antara Bug Bounty dan Penetration Test konvensional?
   a) Bug bounty lebih murah
   b) Bug bounty open-ended dan siapa saja bisa participate; pentest kontrak dan terjadwal
   c) Bug bounty hanya untuk web app
   d) Tidak ada perbedaan

2. Apa yang harus dilakukan researcher ketika menemukan asset yang疑似 di luar scope tapi memiliki kerentanan?
   a) Langsung test dan report
   b) Abaikan karena di luar scope
   c) Verifikasi apakah asset tersebut benar-benar ada di scope, baru test jika confirmed
   d) Share ke researcher lain di forum

3. Safe harbor clause di platform bug bounty melindungi researcher dari:
   a) Semua aktivitas testing tanpa batas
   b) Aktivitas yang mengikuti rules of engagement program
   c) Pelanggaran hukum di semua yurisdiksi
   d) Semua bentuk disclosure

4. Apa urutan yang paling efisien untuk memulai hunting di program baru?
   a) Langsung scan semua endpoint yang ditemukan
   b) Submit duplicate report secepat mungkin
   c) Baca scope → Recon → Attack surface mapping → Manual testing
   d) Gunakan automated scanner saja

5. Mengapa dokumentasi aktivitas hunting itu penting?
   a) Untuk menunjukkan progress ke platform
   b) Untuk bukti legal jika ada masalah
   c) Untuk reproducibility report dan tracking findings, bukti bahwa testing dilakukan dalam scope
   d) Tidak penting, cukup ingat di kepala

**Kunci Jawaban:** 1-B, 2-C, 3-B, 4-C, 5-C

## Assignment

1. **Environment Setup (wajib):** Install Kali Linux di VM, konfigurasi Burp Suite dengan FoxyProxy, install minimal 5 tools recon (subfinder, httpx, ffuf, nmap, amass). Screenshot hasil dan push ke Obsidian vault.

2. **Platform Exploration:** Buat akun di minimal 2 platform bug bounty. Untuk 5 program yang berbeda, analisis scope-nya dan buat comparison table. Identifikasi program mana yang paling cocok untuk beginner.

3. **Documentation Setup:** Buat Obsidian vault dengan structure: `Daily-Notes/`, `Programs/`, `Findings/`, `Reports/`, `Recon-Data/`. Buat template note untuk tracking program hunt.

4. **Legal Research:** Cari 2 kasus nyata di Indonesia atau globally di mana researcher menghadapi masalah legal karena aktivitas bug bounty. Analisis apa yang salah dan bagaimana cara menghidarinya.

## Template Report Bug Bounty

```markdown
# Bug Report Template

## Summary
[Kolom singkat 2-3 kalimat: apa vulnerability, di mana ditemukan, impact singkat]

## Platform
HackerOne / Bugcrowd / Intigriti / YesWeHack / lainnya

## Program/Target
[Nama program, URL target]

## Severity
[Critical / High / Medium / Low / Informative]
[CVSS 3.1 Score: X.X (Vector: AV:N/AC:L/...]

## Vulnerability Type
[Contoh: IDOR, SQL Injection, Information Disclosure, dll]

## Asset/Endpoint
[URL lengkap atau subdomain yang affected]

## Description
[Penjelasan teknis vulnerability — apa yang terjadi, komponen yang terlibat,
request/response yang relevan]

## Steps to Reproduce
1. [Langkah 1]
2. [Langkah 2]
3. [Langkah 3]

## Impact
[Apa yang bisa dilakukan attacker dengan bug ini? Siapa yang affected?
Apakah ada data yang bisa diekstrak?]

## Evidence
[Screen recording, HAR file, screenshot request/response]
<!-- atau lampirkan file -->

## Remediation / Recommendation
[Penjelasan langkah yang harus dilakukan developer untuk fix]
```

---

*Module ini adalah fondasi. Jika environment belum ready, peserta tidak akan bisa mengikuti sesi-sesi berikutnya dengan efektif. Invest waktu di sini dengan benar.*