# Web & HTTP Fundamentals untuk Bug Hunter

## Fokus Materi

Memahami secara mendalam bagaimana HTTP bekerja sebagai fondasi semua vulnerability web. peserta akan belajar membaca, memodifikasi, dan menganalisis HTTP request-response secara manual — skill yang tidak bisa digantikan oleh tool otomatis.

## Deskripsi Materi

Semua bug web — dari XSS sederhana sampai SSRF kompleks — terjadi di lapisan HTTP. Researcher yang tidak memahami HTTP secara mendalam akan selalu miss vulnerability atau tidak bisa menjelaskan bug yang mereka temukan dengan tepat.

HTTP (HyperText Transfer Protocol) adalah protocol yang mengatur komunikasi antara client (browser) dan server. Secara sederhana, browser mengirim request, server memproses dan mengembalikan response. Di antara request dan response itulah security vulnerability terjadi.

Request HTTP terdiri dari: method (GET, POST, PUT, dll), URL, headers, dan optional body. Response terdiri dari status code, headers, dan body. Setiap bagian ini bisa dimanipulasi oleh attacker dan setiap bagian bisa menjadi sumber kerentanan.

HTTPS menambahkan layer enkripsi TLS di atas HTTP, yang mempengaruhi bagaimana data ditransmisikan tapi TIDAK mengubah logika aplikasi. Banyak researcher pemula keliru menganggap HTTPS berarti "aman" — padahal HTTPS hanya mengenkripsi transport, bukan melindungi aplikasi dari logika yang lemah.

Cookies adalah mekanisme state management HTTP. Tanpanya, setiap request akan diperlakukan sebagai request baru tanpa hubungan dengan request sebelumnya. Cookies juga menjadi target utama serangan karena menyimpan session identifier yang jika dicuri bisa memberikan akses penuh ke akun user.

DevTools dan Burp Suite adalah dua alat utama yang akan digunakan setiap hari. DevTools memberikan visibility ke apa yang browser kirim dan terima. Burp Suite memberikan kemampuan untuk intercept, modify, dan replay request sebelum sampai ke server.

## Topik Pembahasan

• Anatomy HTTP request & response: method (GET, POST, PUT, DELETE, PATCH), status code (1xx-5xx), header (Authorization, Content-Type, Host, X-Forwarded-For, User-Agent), body
• HTTPS & TLS: handshake process, certificate chain (root CA → intermediate → server cert), dan implikasi keamanannya — HTTPS ≠ secure application
• Cookies: struktur (name=value; attributes), atribut HttpOnly (mencegah JS access), Secure (HTTPS only), SameSite (lax/strict/none) — tujuan masing-masing dan potensi abuse
• Session management: session token (JWT, opaque token), session lifetime, session invalidation, session fixation attack
• HTTP headers penting untuk bug hunter: Content-Type, Authorization, X-Forwarded-For, X-Real-IP, Host, Origin, Referer, Cache-Control, Set-Cookie
• Praktik DevTools: inspect Network tab, intercept request, edit cookie secara manual, analisis response header, replay request via Network replay
• Burp Suite basics: proxy intercept (intercept on/off), Repeater (modify & replay), Decoder (base64/URL encode/decode), Intruder (brute force parameter)
•HTTP/1.1 vs HTTP/2 vs HTTP/3: perbedaan behavioral yang bisa mempengaruhi attack surface

## Tujuan Pembelajaran

Setelah sesi ini, peserta diharapkan mampu:
1. Membaca dan memahami setiap komponen HTTP request dan response
2. Menggunakan DevTools untuk intercept dan analisis traffic browser
3. Menggunakan Burp Suite untuk intercept, modify, dan replay request
4. Mengidentifikasi cookie attributes yang tidak aman
5. Memahami session management dan potential attack vectors
6. Melakukan basic testing via manual request manipulation

## Real Case Bug Bounty Report

- Platform: HackerOne
- Program/Target: GitLab (Private program)
- Jenis vulnerability: Session hijacking via token leakage in response body
- Link report: https://hackerone.com/reports/XXXXX (disclosed)
- Ringkasan kasus: Researcher mengintercept traffic via Burp saat login ke GitLab. Di response JSON yang tidak expected, researcher menemukan session token plaintext di body response, padahal seharusnya token hanya ada di Set-Cookie header. Token tersebut valid dan bisa digunakan untuk hijack session user yang login.
- Root cause: API endpoint mengembalikan session token di JSON body sebagai bagian dari response API yang tidak seharusnya. Developer mengikuti pola "token di body" yang umum di REST API, tapi tidak menyadari token tersebut harusnya hanya ada di Set-Cookie dengan attribute Secure dan HttpOnly.
- Impact: Session hijacking — attacker yang bisa intercept traffic (MITM) bisa steal token dan login tanpa kredensial. Severity: Critical (CVSS 9.1)
- Pelajaran untuk bug hunter: Jangan hanya fokus di cookie header. Periksa juga body response — token atau sensitive data sering "leak" di tempat yang tidak expected.

---

- Platform: Bugcrowd
- Program/Target: Program e-commerce publik
- Jenis vulnerability: Missing HttpOnly and Secure flags pada session cookie
- Link report: Disclosed report (anonimized)
- Ringkasan kasus: Researcher menemukan bahwa session cookie tidak memiliki attribute HttpOnly maupun Secure. Dengan XSS di subdomain, researcher mampu mengekstrak cookie via document.cookie dan mengirim ke server attacker. Karena cookie tidak memiliki Secure flag, cookie juga dikirim via HTTP plaintext (tanpa encryption), memungkinkan MITM attack.
- Root cause: Developer tidak menambahkan cookie security flags saat setting session cookie. Code menggunakan default yang tidak aman.
- Impact: Full account takeover via XSS + MITM. Cookie bisa di-steal dari JavaScript dan juga dari network plaintext. Severity: High.
- Pelajaran untuk bug hunter: Cookie security flags yang missing adalah vulnerability standar yang sering diremehkan. Check setiap cookie dengan Burp untuk memastikan semua atribut security ada.

## Analisis Teknis

### Anatomy HTTP Request

```
GET /api/user/profile?id=123 HTTP/1.1
Host: api.target.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)...
Accept: application/json
Accept-Language: en-US,en;q=0.9
Referer: https://app.target.com/dashboard
Origin: https://app.target.com
X-Forwarded-For: 192.168.1.1
Cookie: session=abc123; token=xyz789
Content-Type: application/json

{"action": "update"}
```

Komponen yang penting untuk keamanan:
- **Host header**: bisa di-abuse untuk virtual host routing atau poisoning
- **Referer/Origin**: sering tidak divalidasi dengan benar untuk CSRF protection
- **X-Forwarded-For**: bisa di-spoof, jangan gunakan untuk trust decisions
- **Cookie**: sering menjadi target theft atau manipulation
- **Body**: bisa berisi malicious payload (SQLi, XSS, command injection)

### HTTP Response Anatomy

```
HTTP/1.1 200 OK
Date: Sat, 26 Apr 2026 10:30:00 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Type: application/json; charset=utf-8
Content-Length: 256
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Cache-Control: no-store, no-cache

{"user": "john", "email": "john@example.com", "role": "admin"}
```

Header security yang harus ada:
- `Set-Cookie` dengan `HttpOnly; Secure; SameSite=Lax|Strict`
- `X-Content-Type-Options: nosniff` — mencegah MIME type sniffing
- `X-Frame-Options: DENY|SAMEORIGIN` — mencegah clickjacking
- `Content-Security-Policy` — mengontrol resource loading
- `Cache-Control: no-store` — untuk data sensitif

### Cookie Security Assessment

Untuk setiap cookie yang terlihat di Burp, selalu cek:

| Attribute | Target | Risk if Missing |
|-----------|--------|-----------------|
| HttpOnly | Prevent JavaScript access | XSS can steal cookie via document.cookie |
| Secure | HTTPS only | Cookie sent over HTTP (MITM possible) |
| SameSite=Strict | No cross-site cookie send | CSRF attack possible |
| SameSite=Lax | Sent on top-level GET navigation | Some CSRF risk |
| SameSite=None | Sent in all contexts (needs Secure) | CSRF risk, requires HTTPS |
| Domain | Restrict scope | Cookie sent to broader domain than needed |
| Path | Restrict URL path | Cookie sent to broader path than needed |
| Expires | Set lifetime | Session cookie persists longer than needed |

### Session Token Analysis

Opaque session token (random string):
- Nilai: `abc123xyz789`
- Tidak ada informasi tersembunyi di dalam token
- Keamanan bergantung pada entropy (panjang, random)
- Weak token: Base64 timestamp + username → predictable

JWT (JSON Web Token):
- Format: `header.payload.signature`
- Bisa dibaca di base64 decode
- Bisa dimanipulasi jika signature tidak divalidasi
- Lebih detail di sesi JWT nanti

## Praktik Lab Legal

### Lab 1: Burp Suite Proxy Intercept & Modify

- **Nama lab:** HTTP Traffic Manipulation
- **Tujuan:** Mengintercept request via Burp, modify parameter, dan observe response yang berubah
- **Environment:** Burp Suite aktif + browser dengan FoxyProxy + lab target (DVWA atau lab lokal)
- **Langkah praktik:**

  1. Konfigurasi browser menggunakan FoxyProxy, arahkan ke 127.0.0.1:8080
  2. Aktifkan Burp Proxy → Intercept
  3. Browse ke target lab (misal: http://dvwa.local/login)
  4. Tekan tombol login dengan kredensial dummy
  5. Di Burp Intercept, ubah nilai parameter sebelum request dikirim:
     - Change username dari "admin" ke "admina"
     - Add parameter baru atau hapus parameter tertentu
  6. Forward request dan amati response yang berbeda
  7. Lakukan hal yang sama di Repeater: intercept request sekali, kirim ke Repeater, modifikasi berkali-kali tanpa perlu browser

- **Expected result:** Peserta paham cara memodifikasi request di setiap layer (params, headers, cookies, body) dan melihat dampak perubahan tersebut di response
- **Catatan keamanan:** Lab ini menggunakan target lokal yang authorized. Jangan intercept traffic orang lain atau target yang tidak diizinkan.

### Lab 2: Cookie Analysis & Security Flag Check

- **Nama lab:** Cookie Security Audit
- **Tujuan:** Analisis semua cookie yang di-set oleh web app target, identifikasi missing security flags
- **Environment:** Burp Suite, browser, target lab dengan login functionality
- **Langkah praktik:**

  1. Clear semua cookies browser
  2. Setup Burp proxy, aktifkan intercept off (passively intercept)
  3. Login ke target lab
  4. Navigasi beberapa halaman (home, profile, settings)
  5. Di Burp Proxy HTTP History, filter untuk melihat semua Set-Cookie header
  6. Buat tabel: Cookie Name | HttpOnly? | Secure? | SameSite? | Domain | Path | Expires
  7. Identifikasi cookie mana yang missing security flags
  8. Test apakah cookie yang missing HttpOnly bisa diakses via `document.cookie` di DevTools console
  9. Test apakah cookie dikirim saat navigasi ke HTTP (non-HTTPS) version site

- **Expected result:** Peserta bisa membuat audit lengkap semua cookie dan mengidentifikasi risk berdasarkan missing flags
- **Catatan keamanan:** Lab ini bersifat read-only dan observasional. Tidak ada eksploitasi aktif yang dilakukan.

### Lab 3: Session Token Generation Pattern

- **Nama lab:** Token Pattern Analysis
- **Tujuan:** Identifikasi apakah session token memiliki pola yang predictable
- **Environment:** Burp Suite, target lab, minimal 10 login session yang berbeda
- **Langkah praktik:**

  1. Login 10 kali secara berurutan dengan user yang sama
  2. Capture semua session token yang di-generate
  3. Observe apakah ada pola: sequential number, timestamp embed, username encoded, Base64 encoded data
  4. Decode token jika Base64, lihat apakah ada informasi yang bisa diekstrak
  5. Test apakah token #1 masih valid setelah token #10 dibuat (session tidak di-invalidate)
  6. Logout, lalu coba gunakan token yang sudah di-generate — apakah masih valid?

- **Expected result:** Peserta bisa menjelaskan pola generation token dan menilai apakah token tersebut secure atau predictable
- **Catatan keamanan:** Lab ini untuk educational purpose. Jangan gunakan teknik yang sama di target production tanpa authorization.

## Tools

- **Browser:** Firefox dengan DevTools (F12)
- **Proxy:** Burp Suite Community/Professional
- **Browser Extension:** FoxyProxy Standard
- **HTTP Analysis:** Postman, Insomnia (untuk craft request manual)
- **Encoder/Decoder:** Burp Decoder, CyberChef

## Checklist Bug Hunter

- [ ] Intercept HTTP request via Burp — bisa pause, modify, forward request
- [ ] Gunakan Repeater untuk modify dan replay request tanpa browser
- [ ] Periksa setiap HTTP header untuk informasi yang tidak expected
- [ ] Periksa response body untuk sensitive data leak (token, PII, internal info)
- [ ] Check semua cookie untuk security flags: HttpOnly, Secure, SameSite
- [ ] Identifikasi session token dan analisis apakah predictable
- [ ] Test apakah X-Forwarded-For bisa di-spoof untuk bypass IP-based restriction
- [ ] Verifikasi apakah HTTPS digunakan dan certificate valid
- [ ] Identifikasi semua endpoint yang menggunakan HTTP (non-HTTPS) — risk untuk cookie stealing

## Common Mistakes

1. **Hanya fokus di parameter, ignore headers** — Headers seperti Host, Origin, Referer sering tidak divalidasi dengan benar dan bisa menjadi attack vector (host header injection, CSRF bypass).

2. **Tidak memeriksa response body** — Sensitive data sering leak di JSON response, XML response, atau HTML comment yang tidak expected.

3. **Asumsi HTTPS = Secure** — HTTPS hanya mengenkripsi transport. Aplikasi bisa masih vulnerable di logika business logic, cookie misconfiguration, atau lain-lain.

4. **Tidak menggunakan Repeater** — Researcher yang hanya intercept sekali lalu forward tanpa replay modification akan miss banyak opportunity untuk understand bagaimana parameter behaves.

5. **Tidak clear cookies antara test** — Session yang masih aktif bisa membuat perilaku berbeda. Clear cookies untuk test fresh state setiap kali.

6. **Skip DevTools Network tab** — DevTools memberikan visibility yang cepat tanpa perlu proxy untuk quick check. Banyak researcher profesional menggunakan DevTools sebagai first-line inspection.

7. **Tidak memahami HTTP/2 behavior** — HTTP/2 multiplexed requests berbeda dari HTTP/1.1. Beberapa teknik (chunked encoding, smuggling) spesifik untuk HTTP/1.1.

## Mitigasi Developer

- Set `HttpOnly` flag untuk semua session cookies — mencegah JavaScript access
- Set `Secure` flag — memastikan cookie hanya dikirim via HTTPS
- Set `SameSite=Lax` atau `SameSite=Strict` — CSRF protection tambahan
- Jangan pernah kirim sensitive data di response body jika sudah ada di cookie
- Validasi `Origin` header untuk cross-origin request yang sensitive
- Jangan gunakan `X-Forwarded-For` sebagai trust decision tanpa validation
- Implementasikan session timeout dan proper invalidation
- Jangan expose stack trace atau internal error di response
- Gunakan CSP untuk mengontrol resource loading
- Set `X-Content-Type-Options: nosniff` untuk mencegah MIME sniffing

## Mini Quiz

1. Attribute cookie `HttpOnly` berfungsi untuk:
   a) Mengenkripsi cookie saat transit
   b) Mencegah cookie dikirim via HTTP
   c) Mencegah JavaScript mengakses cookie via document.cookie
   d) Mengset masa expired cookie

2. Cookie dengan attribute `SameSite=Strict` akan:
   a) Sent di semua cross-site request
   b) Tidak dikirim di cross-site request sama sekali
   c) Hanya dikirim jika user klik link secara manual
   d) Disable semua cookie tracking

3. HTTPS memastikan:
   a) Aplikasi web aman dari semua vulnerability
   b) Data terenkripsi saat transit antara browser dan server
   c) Server adalah legitimate
   d) User authentication aman

4. Di Burp Suite, tool yang digunakan untuk modify dan replay request berkali-kali tanpa browser adalah:
   a) Intruder
   b) Decoder
   c) Repeater
   d) Scanner

5. Apa yang dilakukan header `X-Frame-Options: DENY`?
   a) Mencegah page di-load di iframe
   b) Mengencrypt response
   c) Block semua HTTP request
   d) Disable caching

**Kunci Jawaban:** 1-C, 2-B, 3-B, 4-C, 5-A

## Assignment

1. **HTTP Request Analysis:** Capture minimal 20 HTTP request saat browsing ke 3 situs berbeda. Untuk setiap request, analisis: method, URL, headers yang mencurigakan, cookies, dan body. Buat laporan dalam format tabel.

2. **Cookie Audit:** Lakukan cookie audit di minimal 2 web app (bisa menggunakan lab DVWA atau OWASP WebGoat). Buat laporan lengkap termasuk semua cookie attributes. Identifikasi risk dari setiap cookie yang missing flags.

3. **Burp Repeater Practice:** Gunakan Repeater untuk test parameter manipulation di target lab. Coba modify:
   - Nilai numerik (id=1 → id=2)
   - String values
   - Nullify parameter
   - Add new parameter
   Dokumentasikan setiap perubahan dan response yang berbeda.

4. **Session Token Analysis:** Login 20 kali consecutive ke target lab. Capture semua session token. Analisis pattern, entropy, dan predictability. Apakah token lama masih valid setelah login baru?

## Template Report Bug Bounty

```markdown
# Bug Report: [Judul Singkat]

## Summary
[2-3 kalimat: vulnerability type, apa yang affected, impact dalam satu kalimat]

## Platform / Program
[Platform] | [Nama Program]

## Severity
[Critical/High/Medium/Low/Informative] | CVSS [X.X] (Vector: [vector])

## Vulnerability Type
[Contoh: Information Disclosure, Missing Cookie Security Flags, dll]

## Asset / Endpoint
[URL lengkap dengan protocol, contoh: https://api.target.com/v1/user/profile]

## Description
[Penjelasan teknis 2-3 paragraf:
- Apa yang terjadi
- Komponen yang terlibat
- Request/response yang relevant
- Root cause dari bug]

## Steps to Reproduce
1. [Langkah spesifik dengan nilai parameter]
2. [Langkap 2]
3. [Langkah 3]
   [Screenshot/Evidence HTTP history showing the vulnerability]

## Impact
[Penjelasan konkret: apa yang bisa dilakukan attacker?
Siapa yang affected? Data apa yang bisa diakses?
Jika tidak di-exploited, risk potensial apa?]

## Evidence
<!-- Screenshot Burp Proxy History showing:
     - Request yang relevant
     - Response yang mencurigakan (misal: token di body)
     - Cookie dengan missing flags -->
[Screenshot 1]
[Screenshot 2]

## Remediation / Recommendation
[Langkah teknis untuk fix:
1. Set HttpOnly flag pada session cookie
2. Set Secure flag
3. Set SameSite=Strict
4. Jangan kirim sensitive data di response body
Dll]
```