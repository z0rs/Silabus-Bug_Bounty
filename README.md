## 🎯 Kurikulum: 7 Sesi Prioritas Utama

### Metodologi Seleksi

Dari 25 sesi yang tersedia, saya mengeliminasi sesi-sesi yang:
- Terlalu advanced untuk fondasi (Sesi 16, 17, 19, 20)
- Impact bounty rendah/sering out-of-scope (Sesi 18)
- Bisa dijadikan self-study/overlap (Sesi 1, 3, 5)
- Niche & butuh toolchain terpisah (Sesi 23)
- Tools-specific bukan vulnerability-focused (Sesi 24)

---

## 📊 Tabel 7 Sesi Terpilih

| Prioritas | Judul Sesi | Level | Alasan Dipilih | Impact di Bug Bounty | Cocok untuk Praktik? |
|:---------:|-----------|:-----:|----------------|----------------------|:---------------------:|
| **#1** | **Sesi 2 — Web & HTTP Fundamentals untuk Bug Hunter** | 🟢 Beginner | Fondasi mutlak. Tanpa paham HTTP request/response, cookies, session, dan DevTools — semua sesi lainnya tidak bisa dipelajari. Ini adalah "bahasa ibu" seorang bug hunter. | Tidak langsung menghasilkan bounty, tapi **100% sesi lain bergantung di sini** | ✅ Sangat mudah — Burp + browser cukup |
| **#2** | **Sesi 4 — Passive & Active Recon, Subdomain Enumeration & Tech Fingerprinting** | 🟡 Beginner–Intermediate | Recon adalah "pintu masuk" ke semua bug. Bug hunter yang tidak bisa mapping attack surface tidak akan menemukan target yang benar. Pipeline recon = skill yang langsung bisa dipakai hari pertama hunting. | **Multiplier effect** — recon yang baik mengarah ke semua bug lainnya | ✅ Sangat mudah — tools CLI, banyak free target |
| **#3** | **Sesi 7 — IDOR, BOLA & Broken Access Control** | 🟡 Intermediate | IDOR secara konsisten menjadi **vuln paling banyak dilaporkan** di HackerOne & Bugcrowd. Hampir setiap web app modern punya resource berbasis ID. Pola serangan repetitif dan bisa diautomasi. | **P1–P3** — dari data leak user hingga full account takeover. Rata-rata bounty $300–$5,000+ | ✅ Sangat mudah — Burp + Autorize, lab DVWA/PortSwigger |
| **#4** | **Sesi 8 — XSS & HTML Injection Mastery** | 🟡 Intermediate | XSS adalah vuln **paling umum secara absolut** di web. Menjadi fondasi semua client-side attacks. Stored XSS + blind XSS bisa chain ke ATO. Wajib dikuasai sebelum belajar CSP Bypass, DOM vulns, dll. | **P2–P4** — dari session hijacking, cookie theft, hingga full ATO via stored XSS | ✅ Mudah — banyak lab gratis (PortSwigger, HackTheBox) |
| **#5** | **Sesi 6 — Broken Authentication & Session Management** | 🟡 Intermediate | ATO (Account Takeover) adalah **target utama program bounty besar**. Auth bugs (reset token, MFA bypass, session fixation) sering berujung P1. Sangat relevan karena hampir semua app punya auth. | **P1–P2** — ATO sering bernilai $1,000–$10,000+ di program enterprise | ✅ Mudah — Burp Intruder, analisis response manual |
| **#6** | **Sesi 13 — SSRF (Server-Side Request Forgery)** | 🟠 Intermediate–Advanced | SSRF adalah **vuln paling berbahaya di era cloud**. Satu SSRF di AWS/GCP bisa berujung RCE via metadata API. Makin banyak muncul karena integrasi webhook, PDF generator, image fetcher di SaaS modern. | **P1–P2** — SSRF ke cloud metadata = critical. Banyak bounty $5,000–$25,000+ | ✅ Sedang — butuh Burp Collaborator/Interactsh, lab cloud sim |
| **#7** | **Sesi 22 — API Security (REST & GraphQL)** | 🟠 Intermediate–Advanced | Dunia sudah **API-first**. Hampir semua aplikasi modern expose REST/GraphQL. OWASP API Top 10 (BOLA, Mass Assignment, Excessive Data Exposure) adalah pola yang terus muncul di setiap program modern. GraphQL introspection sering terabaikan. | **P1–P3** — Mass assignment ke privilege escalation, BOLA ke data leak masif | ✅ Sedang — Postman/Insomnia + Burp, banyak API publik untuk latihan |

---

## ❌ Mengapa Sesi Lain Tidak Diprioritaskan

| Sesi | Alasan Tidak Diprioritaskan |
|------|----------------------------|
| **Sesi 1** (Ecosystem & Setup) | Bisa self-study, tidak ada konten teknikal mendalam. Lebih cocok jadi pre-reading/onboarding |
| **Sesi 3** (JWT/OAuth/CORS Concepts) | Berharga sebagai teori, tapi overlap dengan Sesi 6 & 21. Bisa diintegrasikan ke Sesi 6 |
| **Sesi 5** (Attack Surface Mapping) | Bagus, tapi kontennya bisa digabung ke Sesi 4 tanpa kehilangan substansi |
| **Sesi 9** (CSRF/Clickjacking) | Impact menurun drastis sejak SameSite=Lax jadi default di browser modern. Banyak program anggap low/informational |
| **Sesi 10** (SQL Injection) | Masih relevan, tapi modern framework (ORM, parameterized query) drastis mengurangi frekuensinya. Lebih cocok sebagai modul lanjutan |
| **Sesi 11** (NoSQL Injection) | Frekuensi lebih rendah dari SQLi, niche pada stack MongoDB. Bukan fondasi |
| **Sesi 12** (File Upload/LFI) | Penting, tapi butuh kondisi spesifik (PHP app, file server). Lebih cocok modul intermediate lanjutan |
| **Sesi 14** (XXE/Command Injection) | High impact tapi frekuensi makin rendah di modern app. Lebih cocok advanced track |
| **Sesi 15** (Business Logic) | Susah dijadikan lab standar karena sangat context-dependent per aplikasi |
| **Sesi 16** (SSTI/Deserialization) | Very advanced, butuh deep understanding bahasa pemrograman spesifik |
| **Sesi 17** (Race Conditions) | Butuh pemahaman concurrent programming, susah di-reproduce konsisten untuk pemula |
| **Sesi 18** (DDoS/Rate Limit) | Sering out-of-scope di program bounty. Impact bounty rendah dibanding effort |
| **Sesi 19** (HTTP Smuggling) | Sangat advanced, niche, butuh setup kompleks. Bukan foundational |
| **Sesi 20** (CSP Bypass) | Harus kuasai XSS dulu secara mendalam. Ini adalah level lanjutan dari Sesi 8 |
| **Sesi 21** (OAuth/JWT Advanced) | Overlap dengan Sesi 6, lebih cocok sebagai advanced extension |
| **Sesi 23** (Mobile App) | Butuh toolchain & knowledge terpisah (Android/APK). Bukan core web bug bounty |
| **Sesi 24** (AI/Hexstrike) | Tool-specific, bisa berubah cepat. Bukan skill fundamental yang transferable |
| **Sesi 25** (Reporting) | Penting tapi bisa dijadikan modul pendek/worksheet, bukan sesi penuh mandiri |

---

## 🗓️ Urutan Pembelajaran Ideal

```
FASE 1 — FONDASI (2 Sesi)
  ↓
  Sesi 2: HTTP Fundamentals     ← Wajib pertama, semua bergantung di sini
  ↓
  Sesi 4: Recon & Attack Surface ← Bangun pipeline hunting dari awal

FASE 2 — CORE VULNERABILITIES (3 Sesi)
  ↓
  Sesi 7: IDOR & Access Control ← Bug paling umum, mulai dari yang paling sering ketemu
  ↓
  Sesi 8: XSS Mastery           ← Fondasi client-side, banyak chain ke sesi lain
  ↓
  Sesi 6: Broken Auth & Session ← Chain dari XSS dan IDOR menuju ATO

FASE 3 — MODERN & HIGH-IMPACT (2 Sesi)
  ↓
  Sesi 22: API Security         ← Modern attack surface, semua app punya API
  ↓
  Sesi 13: SSRF                 ← High-impact cloud bug, leverage dari recon & API knowledge
```

---

## 👥 Rekomendasi Target Audience

| Sesi | Target Audience |
|------|----------------|
| Sesi 2 (HTTP Fundamentals) | 🟢 **Beginner** — Zero to hero, wajib untuk siapa pun |
| Sesi 4 (Recon) | 🟢 **Beginner** — Bisa langsung praktik hari pertama |
| Sesi 7 (IDOR) | 🟡 **Beginner–Intermediate** — Pola sederhana tapi high value |
| Sesi 8 (XSS) | 🟡 **Intermediate** — Butuh pemahaman HTTP dulu |
| Sesi 6 (Auth) | 🟡 **Intermediate** — Butuh pemahaman session & cookies |
| Sesi 22 (API Security) | 🟠 **Intermediate** — Butuh pemahaman HTTP & IDOR |
| Sesi 13 (SSRF) | 🟠 **Intermediate–Advanced** — Butuh pemahaman network & cloud basic |

---

## 📝 Ringkasan Akhir

> **Mengapa 7 sesi ini adalah pilihan terbaik?**

Ketujuh sesi ini membentuk **"minimum viable curriculum"** yang paling efisien untuk menghasilkan bug hunter yang siap berburu di program nyata. Berikut alasannya:

**1. Coverage Maksimal, Effort Minimal** — Ketujuh topik ini mencakup lebih dari **70% bug valid yang dilaporkan di HackerOne dan Bugcrowd** berdasarkan data Hacktivity publik. Belajar 7 sesi ini = lebih produktif dari belajar 25 sesi secara dangkal.

**2. Vertical Stack yang Lengkap** — Kurikulum ini mencakup semua layer: network/protocol (HTTP), discovery (Recon), business logic (IDOR/Auth), client-side (XSS), modern API, dan server-side advanced (SSRF). Tidak ada blind spot mayor.

**3. Chain-ability Tinggi** — Setiap sesi saling enable satu sama lain: Recon → temukan endpoint API → IDOR → chain ke Auth bug → chain ke XSS stored → ATO. Ini adalah **bug chaining mindset** yang dipakai hunter top.

**4. Lab-Friendly** — Semua bisa dipraktikkan di PortSwigger Web Academy (gratis), DVWA, HackTheBox, atau program VDP publik tanpa perlu setup kompleks.

**5. ROI Bounty Tertinggi** — Kombinasi frekuensi tinggi (IDOR, XSS) dan impact tinggi (Auth ATO, SSRF cloud) memberi peluang paling realistis untuk **first bounty dalam 30–60 hari** bagi pemula yang serius.
