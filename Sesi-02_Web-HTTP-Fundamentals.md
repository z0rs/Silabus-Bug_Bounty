# Sesi 02 — Web & HTTP Fundamentals untuk Bug Hunter

> **Level:** Beginner  
> **Durasi Estimasi:** 3–4 jam (teori + praktik)  
> **Prasyarat:** Tidak ada — ini adalah sesi fondasi  
> **Tools:** Burp Suite Community, Browser (Firefox/Chrome), DevTools

---

## 🎯 Tujuan Pembelajaran

Setelah menyelesaikan sesi ini, peserta mampu:
- Membaca, menganalisis, dan memodifikasi HTTP request/response secara manual
- Memahami peran cookies, session token, dan header keamanan
- Menggunakan Burp Suite sebagai proxy dasar
- Menggunakan DevTools untuk analisis request langsung di browser
- Mengidentifikasi anomali HTTP yang menjadi akar dari bug bounty

---

## 📚 Bagian 1 — Anatomy HTTP Request & Response

### 1.1 Apa Itu HTTP?

HTTP (HyperText Transfer Protocol) adalah protokol komunikasi antara **client** (browser) dan **server** (web app). Sebagai bug hunter, memahami HTTP bukan sekadar teori — setiap interaksi antara browser dan server adalah **attack surface** potensial.

```
CLIENT (Browser / Burp)                SERVER (Web App)
        │                                      │
        │ ──────── HTTP Request ────────────►  │
        │                                      │
        │ ◄─────── HTTP Response ──────────── │
        │                                      │
```

### 1.2 Struktur HTTP Request

```http
POST /api/v1/login HTTP/1.1
Host: app.target.com
Content-Type: application/json
Authorization: Bearer eyJhbGci...
Cookie: session=abc123; csrf_token=xyz
User-Agent: Mozilla/5.0 ...
Content-Length: 47

{"username": "user@test.com", "password": "test123"}
```

| Komponen | Penjelasan | Relevansi Bug Bounty |
|----------|-----------|----------------------|
| **Method** | GET, POST, PUT, DELETE, PATCH, OPTIONS | Method lain (PUT/DELETE) sering tidak ter-protect |
| **Path** | `/api/v1/login` | Endpoint discovery & IDOR |
| **HTTP Version** | HTTP/1.1 vs HTTP/2 | HTTP/2 downgrade = smuggling surface |
| **Host Header** | `app.target.com` | Host Header Injection target |
| **Content-Type** | `application/json` | Ubah ke XML → XXE, ubah ke form → CSRF bypass |
| **Authorization** | Bearer token / Basic Auth | Token leakage, JWT manipulation |
| **Cookie** | Session token, CSRF token | Session hijacking, CSRF |
| **Body** | JSON/form data/XML | Injection points (SQLi, SSTI, etc.) |

### 1.3 Struktur HTTP Response

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0
Content-Type: application/json
Set-Cookie: session=newtoken456; HttpOnly; Secure; SameSite=Lax
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
Content-Length: 89

{"status": "success", "user_id": 1337, "role": "admin", "token": "eyJhbGci..."}
```

> 🔍 **Bug Hunter Note:** Response body yang mengandung `role`, `admin`, atau data sensitif yang seharusnya tidak dikembalikan ke client = **Information Disclosure / Excessive Data Exposure**.

### 1.4 HTTP Status Codes yang Penting untuk Bug Hunter

| Status Code | Arti | Relevansi |
|-------------|------|-----------|
| `200 OK` | Sukses | Baseline normal |
| `201 Created` | Resource dibuat | POST berhasil — cek apakah ada IDOR di resource baru |
| `301/302` | Redirect | Open Redirect vector |
| `400 Bad Request` | Request salah | Error message = info disclosure |
| `401 Unauthorized` | Perlu auth | Cek bypass: hapus header, ubah token |
| `403 Forbidden` | Auth ada, tapi dilarang | Sering bisa di-bypass dengan path manipulation |
| `404 Not Found` | Tidak ditemukan | Forced browsing → cari endpoint tersembunyi |
| `500 Internal Server Error` | Error server | Stack trace = info disclosure critical |

---

## 📚 Bagian 2 — HTTPS & TLS: Implikasi Keamanan

### 2.1 Mengapa TLS Penting untuk Bug Hunter?

TLS (Transport Layer Security) mengenkripsi komunikasi antara browser dan server. Sebagai bug hunter yang menggunakan Burp Suite sebagai **Man-in-the-Middle**, kamu perlu memahami cara kerja intercept traffic HTTPS.

```
Browser ──TLS──► Burp Suite (MITM) ──TLS──► Server
                   [Plaintext visible]
```

### 2.2 Setup Burp Suite CA Certificate (Wajib!)

1. Buka Burp Suite → Settings → Proxy → Proxy Listeners (port 8080)
2. Buka browser, set proxy ke `127.0.0.1:8080`
3. Navigasi ke `http://burp` → Download CA Certificate
4. Install di browser: Firefox → Settings → Privacy → Certificates → Import

> ⚠️ **Jika CA cert tidak diinstall:** Semua HTTPS traffic akan di-block browser karena sertifikat Burp tidak dipercaya.

---

## 📚 Bagian 3 — Cookies: Fondasi Session Management

### 3.1 Anatomy Cookie

```http
Set-Cookie: session_id=a3f9b2c1d4e5; 
            HttpOnly; 
            Secure; 
            SameSite=Lax; 
            Path=/; 
            Domain=.target.com;
            Expires=Wed, 09 Jun 2024 10:18:14 GMT
```

### 3.2 Flag Cookie & Implikasinya

| Flag | Ada | Tidak Ada | Dampak Jika Hilang |
|------|-----|-----------|---------------------|
| **HttpOnly** | JS tidak bisa akses | JS bisa baca cookie | XSS → Cookie Theft → Session Hijack |
| **Secure** | Hanya kirim via HTTPS | Kirim via HTTP juga | Cookie bisa di-sniff di jaringan tidak aman |
| **SameSite=Strict** | Tidak dikirim di cross-site request | — | CSRF protection kuat |
| **SameSite=Lax** | Hanya dikirim di top-level navigation | — | CSRF protection medium |
| **SameSite=None** | Selalu dikirim, butuh Secure | — | CSRF rentan jika Secure hilang |

### 3.3 Real Case: Cookie Misconfiguration

> **📌 Real Case — Terinspirasi dari pola umum HackerOne disclosed reports**
> 
> Peneliti menemukan bahwa endpoint `/api/user/profile` mengembalikan session cookie baru tanpa flag `HttpOnly`. Ketika XSS ditemukan di halaman komentar, cookie bisa dicuri via `document.cookie` dan digunakan untuk account takeover.
> 
> **Chain:** Missing `HttpOnly` + Stored XSS → Session Hijacking → Full ATO  
> **Severity:** High (P2)

---

## 📚 Bagian 4 — Session Management

### 4.1 Cara Kerja Session

```
1. User login → Server buat session token → Simpan di DB
2. Server kirim token ke browser via Set-Cookie
3. Setiap request, browser kirim cookie → Server validasi
4. Logout → Server hapus session dari DB (seharusnya)
```

### 4.2 Karakteristik Session Token yang Aman

| Kriteria | Aman | Tidak Aman |
|----------|------|------------|
| **Entropi** | 128+ bit random | `user_1234_timestamp` (predictable) |
| **Panjang** | 32+ karakter hex | 8 karakter |
| **Invalidasi** | Dihapus saat logout | Tetap valid setelah logout |
| **Rotasi** | Baru setelah login | Token sama sebelum/sesudah login |

### 4.3 Mendeteksi Session Token Lemah di Burp

1. Buka Burp → Sequencer
2. Capture request yang mengandung token
3. Start Live Capture → Analisis bit entropy
4. Jika entropy < 100 bit → **Potentially predictable token**

---

## 📚 Bagian 5 — HTTP Headers Penting untuk Bug Hunter

### 5.1 Request Headers yang Sering Menjadi Bug Vector

```http
# Host Header — Target: Host Header Injection
Host: target.com

# X-Forwarded-For — Target: IP Bypass, SSRF
X-Forwarded-For: 127.0.0.1

# X-Original-URL / X-Rewrite-URL — Target: Access Control Bypass
X-Original-URL: /admin/panel

# Content-Type — Target: XXE, CSRF Bypass
Content-Type: application/xml

# Origin — Target: CORS Misconfiguration
Origin: https://evil.attacker.com

# Referer — Target: Info Leakage, Open Redirect
Referer: https://app.target.com/reset?token=secret123
```

### 5.2 Response Headers yang Harus Diperiksa

```http
# Jika tidak ada → Clickjacking possible
X-Frame-Options: DENY

# Jika tidak ada → MIME sniffing possible  
X-Content-Type-Options: nosniff

# Jika tidak ada / lemah → XSS possible
Content-Security-Policy: default-src 'self'

# Jika ada → info disclosure (versi server)
Server: Apache/2.4.41 (Ubuntu)

# Jika tidak ada → HSTS not enforced
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

---

## 📚 Bagian 6 — Burp Suite: Workflow Dasar Bug Hunter

### 6.1 Komponen Utama Burp Suite

```
┌─────────────────────────────────────────┐
│              BURP SUITE                  │
│                                          │
│  Proxy ──► Intercept & Modify Requests   │
│  Repeater ──► Replay & Modify Requests   │
│  Decoder ──► Encode/Decode Data          │
│  Intruder ──► Fuzzing & Brute Force      │
│  Sequencer ──► Analyze Token Entropy     │
│  Scanner ──► Auto Vulnerability Scan     │
└─────────────────────────────────────────┘
```

### 6.2 Workflow Dasar: Intercept → Modify → Forward

```
1. Proxy → Intercept ON
2. Browser → aksi di target (login, submit form, dll)
3. Burp menangkap request → MODIFIKASI
4. Forward (kirim ke server)
5. Analisis response
```

### 6.3 Menggunakan Repeater untuk Manual Testing

```
Cara pakai:
1. Klik kanan request di Proxy → "Send to Repeater"
2. Tab Repeater → modifikasi parameter
3. Klik "Send" → lihat response
4. Bandingkan response berbeda → identifikasi anomali

Tips:
- Ubah ID user: /api/user/123 → /api/user/124
- Ubah method: GET → POST
- Hapus Authorization header
- Ubah Content-Type
```

### 6.4 Decoder: Decode Data yang Ter-encode

```
Contoh use case:
- Cookie: dXNlcjoxMjM0 → Decode Base64 → user:1234
- JWT: eyJhbGci... → Decode tiap bagian
- URL encoding: %3Cscript%3E → <script>
- HTML entity: &lt;script&gt; → <script>
```

---

## 📚 Bagian 7 — Browser DevTools untuk Bug Hunter

### 7.1 Network Tab: Analisis Semua Request

```
Cara buka: F12 → Network tab → Reload halaman

Yang harus diperhatikan:
1. Filter by XHR/Fetch → lihat API calls
2. Klik request → Headers tab → lihat semua header
3. Response tab → lihat data yang dikembalikan
4. Initiator tab → tahu script mana yang trigger request
```

### 7.2 Storage Tab: Lihat Cookie & Local Storage

```
Application tab (Chrome) / Storage tab (Firefox):
- Cookies → lihat semua cookie, nilai, flag
- Local Storage → token tersimpan di sini? (tidak aman!)
- Session Storage → data sementara
- IndexedDB → data terstruktur di browser
```

### 7.3 Console: Eksekusi JavaScript

```javascript
// Lihat semua cookie (yang tidak HttpOnly)
document.cookie

// Cek apakah ada token di localStorage
localStorage.getItem('token')
localStorage.getItem('auth')

// Kirim request manual
fetch('/api/user/profile', {
  headers: {'Authorization': 'Bearer ' + localStorage.getItem('token')}
}).then(r => r.json()).then(console.log)
```

---

## 🔴 Real Bug Bounty Cases

### Case 1 — Session Token Tidak Di-invalidasi Setelah Logout

> **Platform:** HackerOne (Public Disclosure Pattern)  
> **Target Type:** SaaS Application  
> **Type:** Broken Session Management

**Skenario:**
Peneliti melakukan login, menyimpan session cookie, kemudian logout. Setelah logout, peneliti mengirim ulang request dengan session cookie lama menggunakan Burp Repeater.

**Yang terjadi:** Server masih menerima session token lama sebagai valid. Artinya, jika token pernah dicuri (via XSS, network sniffing, dll), attacker tetap bisa akses akun meskipun korban sudah logout.

**HTTP Proof:**
```http
# Request setelah logout — seharusnya 401
GET /api/dashboard HTTP/1.1
Host: app.target.com
Cookie: session=a3f9b2c1d4e5   ← token dari sebelum logout

# Response yang tidak seharusnya terjadi
HTTP/1.1 200 OK
{"user": "victim@email.com", "data": {...}}  ← masih valid!
```

**Fix:** Server harus menghapus/invalidasi session dari database saat logout.  
**Severity:** Medium (P3) — escalate ke High jika bisa chain dengan token leakage.

---

### Case 2 — Sensitive Data di Response Body

> **Referensi:** Pola umum dari OWASP API Top 10 #3 (Excessive Data Exposure)  
> **Type:** Information Disclosure

**Skenario:**
Endpoint `/api/v1/user/me` mengembalikan data berlebih di response:

```http
GET /api/v1/user/me HTTP/1.1
Host: app.target.com
Authorization: Bearer [token_user_biasa]
```

```json
{
  "id": 1337,
  "username": "johndoe",
  "email": "john@example.com",
  "role": "user",
  "internal_id": "UUID-xxx",
  "password_hash": "$2b$12$...",     ← TIDAK SEHARUSNYA ADA
  "admin_notes": "Flagged for review", ← TIDAK SEHARUSNYA ADA
  "payment_method": "Visa ending 4242" ← TIDAK SEHARUSNYA ADA
}
```

**Fix:** API harus menerapkan response filtering — kembalikan hanya field yang dibutuhkan frontend.  
**Severity:** Medium–High tergantung sensitivitas data.

---

### Case 3 — HTTP Method Override Bypass

> **Referensi:** Teknik umum yang pernah dilaporkan di beberapa bug bounty program  
> **Type:** Access Control Bypass via Method Override

**Skenario:**
Endpoint DELETE `//api/admin/user/1337` diproteksi dan hanya bisa diakses admin. Namun, server mendukung method override via header.

```http
# Request yang diblokir (403)
DELETE /api/admin/user/1337 HTTP/1.1
Host: app.target.com
Authorization: Bearer [user_token]

# Bypass dengan method override
POST /api/admin/user/1337 HTTP/1.1
Host: app.target.com
Authorization: Bearer [user_token]
X-HTTP-Method-Override: DELETE   ← bypass!

# Response: 200 OK — user berhasil dihapus
```

**Fix:** Nonaktifkan method override, atau pastikan validasi authorization berlaku untuk semua method.  
**Severity:** High (P2) — privilege escalation.

---

## 🛠️ Lab Praktik

### Lab 1 — PortSwigger Web Academy (Gratis)
- 🔗 [HTTP Request Smuggling Labs](https://portswigger.net/web-security/request-smuggling)
- 🔗 [Information Disclosure Labs](https://portswigger.net/web-security/information-disclosure)
- 🔗 [Authentication Labs - Cookie-based](https://portswigger.net/web-security/authentication)

### Lab 2 — OWASP WebGoat
- 🔗 [https://owasp.org/www-project-webgoat/](https://owasp.org/www-project-webgoat/)
- Modul: **HTTP Basics**, **HTTP Proxies**, **Improper Error Handling**

### Lab 3 — TryHackMe
- 🔗 [Burp Suite: The Basics](https://tryhackme.com/room/burpsuitebasics)
- 🔗 [Burp Suite: Repeater](https://tryhackme.com/room/burpsuiterepeater)
- 🔗 [Web Fundamentals](https://tryhackme.com/room/webfundamentals)

### Lab 4 — HackTheBox Academy
- 🔗 [Web Requests Module](https://academy.hackthebox.com/module/details/35)
- 🔗 [Using Web Proxies](https://academy.hackthebox.com/module/details/110)

---

## 📋 Checklist Praktik Mandiri

Setelah mengikuti sesi ini, pastikan kamu bisa:

- [ ] Setup Burp Suite sebagai proxy browser dengan CA cert
- [ ] Intercept, modifikasi, dan forward HTTP request
- [ ] Menggunakan Repeater untuk replay request dengan modifikasi
- [ ] Decode Base64, URL encoding, JWT di Burp Decoder
- [ ] Membaca semua komponen HTTP request & response
- [ ] Mengidentifikasi cookie flags (HttpOnly, Secure, SameSite)
- [ ] Menggunakan DevTools Network tab untuk analisis request
- [ ] Menemukan data sensitif di response body
- [ ] Menguji apakah session token masih valid setelah logout

---

## 📖 Referensi & Bacaan Lanjutan

| Sumber | Link | Topik |
|--------|------|-------|
| OWASP Testing Guide | [WSTG-SESS](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/) | Session Management Testing |
| PortSwigger Web Security | [HTTP Basics](https://portswigger.net/web-security/learning-paths) | HTTP, Cookies, Headers |
| Mozilla MDN | [HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers) | Header reference lengkap |
| Burp Suite Documentation | [Getting Started](https://portswigger.net/burp/documentation/desktop/getting-started) | Burp Suite guide |
| OWASP Cheat Sheet | [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) | Best practices session |

---

## 🔑 Key Takeaways

1. **HTTP adalah bahasa bug hunter** — setiap request/response adalah peluang temuan
2. **Cookie flags bukan opsional** — hilangnya `HttpOnly` atau `Secure` adalah bug yang bisa dilaporkan
3. **Response body sering bocorkan terlalu banyak** — selalu baca response penuh, bukan hanya lihat apakah "berhasil"
4. **Burp Suite adalah ekstensi tangan kamu** — kuasai Proxy, Repeater, dan Decoder sebelum tools lain
5. **HTTP Methods selain GET/POST sering diabaikan developer** — selalu uji PUT, DELETE, PATCH, OPTIONS

---

*Sesi berikutnya: **Sesi 04 — Passive & Active Recon, Subdomain Enumeration & Tech Fingerprinting***
