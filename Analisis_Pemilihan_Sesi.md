# ANALISIS PEMILIHAN SESI
## Linux Hacking ID Bootcamp v4 — Bug Bounty Track

---

## Tabel Pemilihan Sesi

| No Sesi | Judul Sesi | Dipilih? | Level | Alasan Dipilih/Tidak Dipilih | Prioritas |
|---------|-----------|----------|-------|------------------------------|-----------|
| 1 | Bug Bounty Ecosystem, Legal & Lab Setup | **YA** | Beginner | Fondasi mutlak. Tanpa environment siap, peserta tidak bisa mengikuti sesi berikutnya. Legal awareness critical untuk avoid masalah hukum. High impact orientation. | Prioritas Tinggi |
| 2 | Web & HTTP Fundamentals untuk Bug Hunter | **YA** | Beginner | HTTP adalah foundation semua vulnerability web. Researcher yang tidak paham HTTP akan selalu miss bugs. Wajib sebelum sesi technical apapun. | Prioritas Tinggi |
| 3 | Auth & Browser Security Concepts (JWT, OAuth, CORS, CSP) | **YA** | Beginner–Intermediate | Landasan critical untuk semua auth vulnerability di sesi 6, 9, 21. JWT manipulation adalah bug class yang paling sering dibayar. | Prioritas Tinggi |
| 4 | Passive & Active Recon, Subdomain Enumeration & Tech Fingerprinting | **YA** | Beginner–Intermediate | Recon adalah phase paling impactful tapi sering di-skip. Bug bounty terbesar dimulai dari recon yang thorough. Fundamental untuk semua sesi attack. | Prioritas Tinggi |
| 5 | Attack Surface Mapping, Testing Plan & Info Disclosure | **YA** | Intermediate | Bridge dari recon ke attack. Membantu peserta menyusun systematic approach vs random scanning. Info disclosure sering underrated tapi valid dan high frequency. | Prioritas Tinggi |
| 6 | Broken Authentication & Session Management | **YA** | Intermediate | Auth bug = highest bounty impact. Brute force, password reset flaws, session hijacking semua high-impact dan common di real programs. | Prioritas Tinggi |
| 7 | IDOR, BOLA & Broken Access Control | **YA** | Intermediate | OWASP Top 10 + API Security Top 10. IDOR dan BOLA paling sering muncul di modern REST API programs. Beginner-friendly pattern dengan high frequency. | Prioritas Tinggi |
| 8 | XSS & HTML Injection Mastery | **YA** | Intermediate–Advanced | Salah satu bug paling umum di bug bounty. Reflected, stored, DOM, blind — semua variant harus dikuasai. Weaponization dan chaining critical untuk high severity. | Prioritas Tinggi |
| 9 | CSRF, Clickjacking & Open Redirect | **YA** | Intermediate | CSRF bisa elevate limited XSS menjadi full ATO. Open redirect sering undervalued padahal bisa bypass OAuth dan CSP. Sering muncul, sering di-chain. | Prioritas Tinggi |
| 10 | SQL Injection — Manual & Otomasi | **YA** | Intermediate | Meskipun menurun, SQLi tetap salah satu bug paling impactful. Manual skill critical karena SQLMap alone akan miss nuanced vulnerabilities dan tidak bisa bypass WAF. | Prioritas Tinggi |
| 11 | NoSQL Injection & Injection Lanjutan | **YA** | Intermediate | MongoDB-based apps semakin umum. NoSQL injection sering missed karena researcher hanya focus di SQLi. LDAP injection dan HPP menambah breadth. | Prioritas Sedang |
| 12 | File Upload, Path Traversal & LFI/RFI | **YA** | Intermediate–Advanced | File upload bypass ke RCE adalah salah satu attack chain paling valuable. LFI → RCE via log poisoning adalah advanced technique yang perlu dikuasai. | Prioritas Tinggi |
| 13 | SSRF — Server-Side Request Forgery | **YA** | Intermediate–Advanced | SSRF ke cloud metadata adalah bug class dengan highest impact di cloud-native apps. Blind SSRF exploitation critical skill untuk modern attack surface. | Prioritas Tinggi |
| 14 | XXE & OS Command Injection | **YA** | Advanced | XXE di file upload (SVG, DOCX) sering missed. Command injection salah satu path ke RCE paling direct. High impact, membutuhkan skill advanced. | Prioritas Tinggi |
| 15 | Business Logic & Impact Bugs | **YA** | Advanced | Bug bounty tertinggi sering datang dari business logic flaws yang kreativitas-based. Require understanding bisnis model, tidak bisa di-automate. High reward potential. | Prioritas Sedang |
| 16 | SSTI, Deserialization & Prototype Pollution | **YA** | Advanced | Advanced vulnerabilities yang require specific knowledge per engine/language. SSTI dan deserialization bisa lead ke RCE — highest impact. | Prioritas Tinggi |
| 17 | Race Conditions & Concurrent Attack Scenarios | **YA** | Advanced | Sering missed karena require specialized tool (Turbo Intruder) dan understanding timing. Race condition di financial system bisa sangat impactful. | Prioritas Sedang |
| 18 | DDoS, Rate Limiting & Application-Layer DoS | TIDAK | Intermediate–Advanced | DoS testing terbatas di bug bounty karena risk pelanggaran scope. Teknik defensive lebih valuable daripada offensive exploitation di konteks ini. | Ditunda |
| 19 | HTTP Request Smuggling & Cache Attacks | TIDAK | Advanced | Teknik advanced yang membutuhkan environment spesifik untuk test. Bukan beginner-friendly, frequency di program lebih rendah dari kelas bug lain. | Ditunda |
| 20 | CSP Bypass & Advanced Client-Side Attacks | TIDAK | Advanced | Merupakan kelanjutan logis dari sesi XSS (sesi 8). Bisa dimasukkan sebagai advanced module tapi tidak wajib sebagai standalone session untuk beginner track. | Ditunda |
| 21 | OAuth, JWT & CORS/WebSocket/DOM Vulns | TIDAK | Intermediate–Advanced | Banyak overlap dengan sesi 3 (JWT/OAuth/CORS dasar) dan sesi 9 (open redirect/OAuth). Bisa dirangkum atau dijadikan advanced module. | Ditunda |
| 22 | API Security (REST & GraphQL) | TIDAK | Intermediate–Advanced | API security penting tapi sesi 7 (IDOR/BOLA) sudah cover sebagian. Bisa dijadikan module terpisah untuk advanced track, tapi ditunda untuk beginner-focused bootcamp. | Ditunda |
| 23 | Mobile App Bug Bounty & API Interception | TIDAK | Advanced | Membutuhkan environment setup berbeda (Android emulator, Frida). Bisa dijadikan specialization track terpisah, tidak cocok untuk beginner bootcamp core. | Ditunda |
| 24 | AI-Driven Bug Bounty dengan Hexstrike | TIDAK | Intermediate–Advanced | Tool-specific (Hexstrike). Bisa menjadi advanced module setelah fundamental kuat. Untuk beginner bootcamp, focus ke manual skill dulu sebelum automation. | Ditunda |
| 25 | Reporting, Monetization & Certification Roadmap | **YA** | Intermediate | Career-critical module: report writing menentukan apakah bug accepted atau rejected, monetization strategy menentukan career growth, certification roadmap memberikan structured learning path. | Prioritas Tinggi |

---

## Ringkasan Statistik

### Total sesi di silabus: 25 sesi
### Sesi dipilih: **17 sesi**
### Sesi ditunda: **8 sesi**
### Rasio terpilih: 68%

---

## Sesi Prioritas Tinggi (12 sesi)

| No | Judul Sesi | Alasan Prioritas |
|----|-----------|------------------|
| 1 | Bug Bounty Ecosystem, Legal & Lab Setup | Fondasi absolute — tidak ada sesi lain yang bisa dimulai tanpa ini |
| 2 | Web & HTTP Fundamentals untuk Bug Hunter | Fondasi teknis — semua vulnerability layer di HTTP |
| 3 | Auth & Browser Security Concepts (JWT, OAuth, CORS, CSP) | Prerequisite untuk auth bugs di sesi 6, 9, 21 |
| 4 | Passive & Active Recon, Subdomain Enumeration | Bug bounty dimulai dari recon |
| 5 | Attack Surface Mapping, Testing Plan & Info Disclosure | Metodologi systematic hunting |
| 6 | Broken Authentication & Session Management | Auth bug = highest impact, highest frequency |
| 7 | IDOR, BOLA & Broken Access Control | OWASP Top 10/API Top 10, very high frequency |
| 8 | XSS & HTML Injection Mastery | High frequency, multiple variant, high impact |
| 9 | CSRF, Clickjacking & Open Redirect | Bisa chaining untuk escalate impact |
| 10 | SQL Injection — Manual & Otomasi | Classic vulnerability, still impactful |
| 12 | File Upload, Path Traversal & LFI/RFI | Upload bypass → RCE adalah attack chain high value |
| 13 | SSRF — Server-Side Request Forgery | Cloud metadata extraction = critical impact |
| 14 | XXE & OS Command Injection | RCE path, missed by many researchers |
| 16 | SSTI, Deserialization & Prototype Pollution | Advanced RCE techniques |
| 25 | Reporting, Monetization & Certification Roadmap | Career-critical skill |

---

## Sesi Prioritas Sedang (3 sesi)

| No | Judul Sesi | Alasan |
|----|-----------|--------|
| 11 | NoSQL Injection & Injection Lanjutan | LDAP/HPP useful tapi frequency lebih rendah dari SQL/NoSQL |
| 15 | Business Logic & Impact Bugs | High reward tapi butuh pengalaman untuk identify |
| 17 | Race Conditions & Concurrent Attack Scenarios | Sering missed, good differentiator tapi butuh advanced skill |

---

## Sesi yang Ditunda (8 sesi)

| No | Judul Sesi | Alasan Penundaan |
|----|-----------|-----------------|
| 18 | DDoS, Rate Limiting & Application-Layer DoS | Scope risk, teknik defensive lebih valuable |
| 19 | HTTP Request Smuggling & Cache Attacks | Advanced, frequency rendah, butuh environment khusus |
| 20 | CSP Bypass & Advanced Client-Side Attacks | Bisa diintegrasikan ke sesi XSS sebagai advanced module |
| 21 | OAuth, JWT & CORS/WebSocket/DOM Vulns | Overlap dengan sesi 3 dan 9, bisa dirangkum |
| 22 | API Security (REST & GraphQL) | IDOR/BOLA di sesi 7 sudah cover, bisa jadi specialization |
| 23 | Mobile App Bug Bounty & API Interception | Membutuhkan environment berbeda, specialization track |
| 24 | AI-Driven Bug Bounty dengan Hexstrike | Tool-specific, add-on setelah fundamental kuat |
| - | (Session numbers match dari CSV) | |

**Catatan penundaan:** 8 sesi yang ditunda bukan berarti tidak penting. Sesi-sesi ini sebaiknya diajarkan sebagai:
- Advanced track specialization (setelah 17 sesi core selesai)
- Topik选修 untuk researcher yang sudah experienced
- Update material seiring perkembangan bug bounty landscape

---

## Urutan Belajar yang Disarankan

### Fase 1: Foundation (Sesi 1, 2, 3, 4, 5)

```
Minggu 1-2: Sesi 1 - Bug Bounty Ecosystem
  → Pahami landscape, legal boundary, setup environment
  → Assign: Buat bug bounty workflow dan documentation system

Minggu 3-4: Sesi 2 - Web & HTTP Fundamentals
  → Kuasai HTTP lifecycle, cookies, session, Burp Suite
  → Assign: HTTP analysis exercise dan cookie audit

Minggu 5-6: Sesi 3 - Auth & Browser Security (JWT, OAuth, CORS, CSP)
  → Pahami auth modern mechanisms sebelum exploitasinya
  → Assign: JWT manipulation challenge, OAuth flow trace

Minggu 7-8: Sesi 4 - Recon & Subdomain Enumeration
  → Bangun attack surface map dengan passive + active recon
  → Assign: Full recon pipeline untuk target lab

Minggu 9-10: Sesi 5 - Attack Surface Mapping & Info Disclosure
  → Dari recon results ke structured testing plan
  → Assign: Buat testing plan dan attack surface map lengkap
```

### Fase 2: Core Vulnerabilities (Sesi 6, 7, 8, 9, 10, 11, 12)

```
Minggu 11-12: Sesi 6 - Broken Authentication & Session Management
  → Brute force, password reset, session hijacking, MFA bypass
  → Assign: Auth bypass challenge + session analysis report

Minggu 13-14: Sesi 7 - IDOR, BOLA & Broken Access Control
  → Access control testing dengan Autorize + manual testing
  → Assign: IDOR hunt dengan 2 different accounts

Minggu 15-16: Sesi 8 - XSS & HTML Injection Mastery
  → Reflected, stored, DOM, blind — semua variant
  → Assign: Stored XSS dengan XSS Hunter + impact chain

Minggu 17-18: Sesi 9 - CSRF, Clickjacking & Open Redirect
  → CSRF PoC development, open redirect chaining
  → Assign: CSRF impact chain demonstration

Minggu 19-20: Sesi 10 - SQL Injection Manual & Otomasi
  → UNION, error-based, blind, SQLMap mastery
  → Assign: Full SQLi exploitation manual + SQLMap comparison

Minggu 21-22: Sesi 11 - NoSQL Injection & Injection Lanjutan
  → MongoDB operator injection, LDAP, HPP, SSTI primer
  → Assign: NoSQL auth bypass challenge

Minggu 23-24: Sesi 12 - File Upload, Path Traversal & LFI/RFI
  → Upload bypass → web shell → LFI → RCE escalation
  → Assign: Upload to RCE challenge
```

### Fase 3: Advanced Exploitation (Sesi 13, 14, 15, 16, 17)

```
Minggu 25-26: Sesi 13 - SSRF
  → Blind SSRF, cloud metadata, internal service exploitation
  → Assign: Cloud metadata attack demonstration

Minggu 27-28: Sesi 14 - XXE & OS Command Injection
  → XXE via file formats, command injection, reverse shell
  → Assign: XXE + command injection to shell

Minggu 29-30: Sesi 15 - Business Logic & Impact Bugs
  → Price manipulation, workflow bypass, financial impact
  → Assign: Business logic bug hunt + impact quantification

Minggu 31-32: Sesi 16 - SSTI, Deserialization & Prototype Pollution
  → Multi-engine SSTI → RCE, Java/PHP/Python deserialization, PP
  → Assign: SSTI to RCE + deserialization exploitation

Minggu 33-34: Sesi 17 - Race Conditions & Concurrent Attacks
  → Turbo Intruder mastery, TOCTOU, double-spend
  → Assign: Coupon race condition challenge
```

### Fase 4: Professional Development (Sesi 25)

```
Minggu 35-36: Sesi 25 - Reporting, Monetization & Certification
  → Professional report writing, program selection, career roadmap
  → Assign: Tulis minimal 3 professional reports, buat 30-day hunting plan
```

---

## Durasi Total Estimasi

| Fase | Jumlah Minggu | Fokus |
|------|--------------|-------|
| Fase 1: Foundation | 10 minggu | Environment, HTTP, Auth concepts, Recon |
| Fase 2: Core Vulnerabilities | 14 minggu | Auth, IDOR, XSS, CSRF, SQLi, NoSQL, Upload |
| Fase 3: Advanced Exploitation | 10 minggu | SSRF, XXE, Business Logic, SSTI, Race |
| Fase 4: Professional | 2 minggu | Reporting, career |
| **Total** | **36 minggu** | **~9 bulan** |

> **Catatan:** Durasi assumsi 1 sesi = 2 minggu dengan asumsi peserta spending 10-15 jam/minggu. Bisa di-compress untuk intensive bootcamp (4-6 bulan) atau di-expand untuk part-time learning (12-18 bulan).

---

## Prinsip Pemilihan

1. **Frequent & High Impact:** Sesi yang cover vulnerability dengan frequency tinggi di program bug bounty dan impact signifikan (auth, IDOR, XSS, SSRF) diprioritaskan.

2. **Prerequisite Chain:** Sesi disusun agar foundational knowledge tersedia sebelum advanced technique. Misalnya: Sesi 3 (JWT basics) sebelum Sesi 6 (JWT exploitation), Sesi 2 (HTTP) sebelum semua sesi technical.

3. **Beginner-Friendly First:** Sesi untuk beginner-level di awal bootcamp untuk build confidence dan foundation sebelum advanced topics.

4. **Lab-Legal Friendly:** Semua sesi yang dipilih harus bisa dipraktikkan di lab legal (DVWA, OWASP WebGoat, Juice Shop, lab custom) tanpa membutuhkan target production.

5. **High Reference Availability:** Sesi dengan banyak public bug bounty report referensi diprioritaskan agar contoh kasus valid dan tidak di-fabricate.

6. **Differentiator Skill:** Sesi race condition dan business logic bugs dipilih karena skill yang jarang dikuasai researcher pemula — good untuk standout dari competition.

---

*Dokumen ini adalah hasil tahap pipeline curriculum design dan  menghasilkan struktur directory dan 17 file Markdown materi yang siap digunakan sebagai bahan ajar bootcamp.*

---

*Generated: April 2026 — Linux Hacking ID Bootcamp v4*
