# Auth & Browser Security Concepts (JWT, OAuth, CORS, CSP)

## Fokus Materi

Memahami mekanisme autentikasi dan keamanan browser modern yang menjadi landasan exploitation di sesi-sesi auth lanjutan. Fokus pada JWT structure dan weakness, OAuth 2.0 flow, Same-Origin Policy, CORS, dan Content Security Policy.

## Deskripsi Materi

Autentikasi modern di web tidak cukup lagi hanya dengan username-password. Aplikasi modern menggunakan token-based auth (JWT), authorization flow (OAuth 2.0), dan browser security mechanism (SOP, CORS, CSP) untuk mengontrol siapa yang bisa akses apa dan bagaimana data mengalir antar origin.

Namun semua mekanisme ini memiliki subtle vulnerability yang jika tidak dipahami, akan membuat researcher miss kelas bug yang paling impactful: authentication bypass, token manipulation, dan authorization flaws.

JWT (JSON Web Token) adalah standar untuk membuat token yang bisa self-contained — semua informasi ada di dalam token itu sendiri. Struktur JWT terlihat aman karena ada signature, tapi weak signature algorithm atau misconfigured validation membuka pintu bagi attacker untuk forge token dengan privilege yang lebih tinggi.

OAuth 2.0 adalah standar authorization yang mengijinkan third-party app untuk mengakses resource user tanpa memberikan kredensial. Implementasi OAuth yang tidak tepat bisa leak authorization code atau access token ke pihak yang tidak berwenang — membuka jalan untuk account takeover.

Same-Origin Policy (SOP) adalah cornerstone browser security. Ia mencegah script di satu origin mengakses data dari origin lain. Tapi ada banyak exception dan bypass yang legal untuk dikaji — yang bisa jadi attack vector.

CORS (Cross-Origin Resource Sharing) adalah mekanisme untuk relaxation SOP secara controlled. Ketika server mengembalikan header `Access-Control-Allow-Origin`, browser mengijinkan cross-origin request yang biasanya diblokir SOP. CORS misconfiguration adalah bug yang umum dan bisa digunakan untuk csrf-like attack atau data exfiltration.

CSP (Content Security Policy) adalah header yang mengontrol dari mana browser boleh load resource. CSP yang lemah bisa menjadi enabler untuk XSS attack. Researcher perlu bisa baca CSP dan identifikasi weakness.

## Topik Pembahasan

• JWT structure: header.payload.signature — decode manual dengan Base64URL, isi klaim umum (iss, sub, exp, iat, aud)
• JWT algorithms: HS256 (symmetric), RS256 (asymmetric), none (alg:none) — mana yang aman dan mana yang dangerous
• JWT algorithm confusion attack: RS256 → HS256 exploit — menggunakan public key sebagai HMAC secret
• JWT manipulation: modifikasi claim (sub, exp, role) untuk privilege escalation
• OAuth 2.0 authorization code flow: step-by-step walkthrough dari user authorize sampai access token
• OAuth implicit flow: kenapa implicit flow deprecated — token di fragment, leak via Referer
• OAuth state parameter: tujuan CSRF protection, apa yang terjadi jika state tidak divalidasi
• OAuth redirect_uri validation: bagaimana bypass jika validation lemah
• Same-Origin Policy (SOP): apa yang diizinkan/blocked, document.cookie access, XMLHttpRequest, iframe,弹出窗口
• SOP relaxation: CORS, postMessage, JSONP — kapan SOP bisa di-bypass secara legitimate
• CORS header analysis: Access-Control-Allow-Origin, Allow-Credentials, Allow-Methods, Allow-Headers
• Preflight request: OPTIONS method, kapan browser kirim preflight, dan bagaimana meng-exploit
• CORS misconfiguration patterns: wildcard origin dengan credentials, null origin, regex bypass
• Content Security Policy (CSP): directive utama (default-src, script-src, style-src, img-src, connect-src, frame-src)
• CSP bypass technique preview: unsafe-inline, unsafe-eval, whitelist domain abuse, JSONP gadget (detail di sesi 20)

## Tujuan Pembelajaran

Setelah sesi ini, peserta diharapkan mampu:
1. Decode dan анализ JWT secara manual tanpa library
2. Identifikasi weak JWT configuration (alg:none, weak secret, predictable claim)
3. Memahami OAuth 2.0 authorization code flow dan implicit flow secara mendalam
4. Identifikasi OAuth misconfiguration (missing state, weak redirect_uri)
5. Analisis CORS header dan identifikasi misconfiguration patterns
6. Baca dan interpretasi CSP header untuk identifikasi weakness
7. Melakukan testing JWT, OAuth, CORS secara sistematis di target

## Real Case Bug Bounty Report

- Platform: HackerOne
- Program/Target: Private program (披露済み — disclosed)
- Jenis vulnerability: JWT algorithm confusion (RS256 → HS256)
- Link report: https://hackerone.com/reports/XXXXX
- Ringkasan kasus: Researcher mengekstrak public key dari target aplikasi (key publik yang served via endpoint `/api/auth/keys`). Dengan mengubah algorithm dari RS256 ke HS256 di JWT header dan menggunakan public key sebagai HMAC secret, researcher forge token untuk user admin baru.
- Root cause: Server menggunakan public key untuk verify signature HS256, yang seharusnya hanya untuk RS256. Developer salah meng-assign algoritma.
- Impact: Full privilege escalation — generate admin token tanpa kredensial. Severity: Critical (CVSS 9.0)
- Pelajaran untuk bug hunter: Selalu coba ubah algoritma JWT. Jika server tidak validate algorithm dengan benar, RS256 public key bisa digunakan sebagai HS256 secret.

---

- Platform: Intigriti
- Program/Target: Program publik
- Jenis vulnerability: OAuth state parameter missing → CSRF di OAuth flow
- Link report: https://blog.intigriti.com/202X/xx/oauth-csrf-writeup (disclosed researcher's blog)
- Ringkasan kasus: Aplikasi menggunakan OAuth untuk login via Google/GitHub. Researcher menemukan bahwa setelah callback OAuth, server tidak memvalidasi state parameter. Attacker bisa membuat OAuth initiation link yang terikat ke victim session. Victim yang mengklik link akan memberikan authorization ke attacker OAuth app, yang bisa harvest access token.
- Root cause: Developer implementasi OAuth tanpa CSRF protection — state parameter tidak di-set atau tidak divalidasi.
- Impact: Account takeover via OAuth CSRF — attacker bisa link attacker account ke victim session. Severity: High.
- Pelajaran untuk bug hunter: Setiap OAuth flow HARUS punya state parameter. Jika tidak ada atau tidak divalidasi, itu adalah vulnerability.

---

- Platform: Bugcrowd
- Program/Target: Program e-commerce besar
- Jenis vulnerability: CORS misconfiguration — wildcard origin dengan Allow-Credentials
- Link report: Disclosed report (KYC: researcher's disclosure writeup)
- Ringkasan kasus: Researcher menemukan endpoint API yang mengembalikan header `Access-Control-Allow-Origin: *` bersamaan dengan `Access-Control-Allow-Credentials: true`. Kombinasi ini invalid — browser menolak credentials jika origin wildcard. Tapi researcher menemukan bahwa endpoint yang sama juga menerima arbitrary origin via preflight request (karena server meng-echo back Origin header). Attacker bisa membuat page yang fetch data dari API menggunakan victim's cookie.
- Root cause: Server tidak whitelist specific origin, melainkan echo back Origin header tanpa proper validation. Allow-Credentials diijinkan tanpa checking origin.
- Impact: Data exfiltration dari victim's session — attacker page bisa fetch API data using victim's cookie. Severity: High.
- Pelajaran untuk bug hunter: Periksa setiap CORS response dengan Burp. Jangan hanya assume wildcard = tidak useful. Echo-back origin + credentials configuration bisa exploited.

## Analisis Teknis

### JWT Structure & Decoding

JWT terdiri dari 3 bagian yang dipisahkan oleh titik (.):

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

**Header (decode Base64URL):**
```json
{"alg":"HS256","typ":"JWT"}
```

**Payload (decode Base64URL):**
```json
{"sub":"1234567890","name":"John Doe","iat":1516239022,"exp":1516242622,"role":"user"}
```

**Signature:**
HMAC-SHA256( base64url(header) + "." + base64url(payload), secret )

**Claim penting:**
- `iss` (issuer): siapa yang issuing token
- `sub` (subject): identity (user ID)
- `aud` (audience): untuk siapa token ini
- `exp` (expiration): timestamp expired
- `iat` (issued at): kapan di-issue
- `nbf` (not before): tidak valid sebelum timestamp ini
- Custom claims: `role`, `email`, `permissions`

**Tools decode:**
- Online: jwt.io (debugger)
- CLI: `echo "TOKEN" | cut -d. -f2 | base64 -d` (Linux)
- Burp Extension: JWT Editor (PortSwigger)

### JWT Attack Vectors

**1. Algorithm: none (alg:none)**

Jika server menerima `alg: "none"`, signature diabaikan:
```json
{"alg":"none","typ":"JWT"}
{"sub":"admin","role":"user","exp":9999999999}
```

Token tanpa signature = bisa forge arbitrary identity.

**2. Algorithm Confusion (RS256 → HS256)**

Proses:
1. Dapatkan public key dari `/auth/keys` atau endpoint yang serve public key
2. Download public key (PEM format)
3. Buat JWT baru dengan header `alg: HS256` (bukan RS256)
4. Use public key sebagai HMAC secret untuk sign
5. Server menerima JWT, membaca algorithm HS256, menggunakan public key untuk verify HMAC — karena public key served sebagai RS256 key, tapi HMAC symmetric verification menggunakan key yang sama: SUCCESS

**3. Claim Manipulation**

- Modifikasi `sub` atau `user_id` untuk horizontal privilege escalation
- Remove atau modify `exp` untuk bypass expiration check
- Add atau modify `role`, `admin`, `is_admin` claim untuk vertical escalation
- Modifikasi `aud` (audience) untuk bypass token usage restriction

**4. Key Confusion via jku/x5u**

Jika JWT header mengandung `jku` (JWK Set URL) atau `x5u` (X.509 URL), attacker bisa point ke attacker-controlled server yang return attacker key.

### OAuth 2.0 Flow Deep Dive

**Authorization Code Flow:**

```
Step 1: User klik "Login with Google"
   Browser → GET https://accounts.google.com/o/oauth2/v2/auth
           ?client_id=ATTACKER_APP_ID
           &redirect_uri=https://attacker.com/callback
           &response_type=code
           &scope=email profile
           &state=xyz123

Step 2: User authorize
   Browser → Google authorization page → User approve

Step 3: Google redirect ke attacker.com dengan code
   Browser → GET https://attacker.com/callback?code=AUTH_CODE&state=xyz123

Step 4: Attacker exchange code untuk token (di backend)
   Attacker server → POST https://oauth.googleapis.com/token
                   code=AUTH_CODE&client_secret=xxx

Step 5: Attacker dapat access token → bisa akses victim's Google data
```

Ini adalah OAuth CSRF attack. Solution: `state` parameter yang di-bind ke user session dan di-validate di callback.

**Authorization Code vs Implicit Flow:**

| Aspek | Authorization Code | Implicit |
|-------|-------------------|---------|
| Token delivery | Via server-side redirect (code) | Via URL fragment (#access_token=...) |
| Token visibility | Only backend server | Browser + Referer header |
| Security | Lebih aman | Deprecated (leak risk) |

### CORS Misconfiguration Patterns

**Pattern 1: Echo-back Origin dengan Credentials**
```
Request:  Origin: https://evil.com
Response: Access-Control-Allow-Origin: https://evil.com
          Access-Control-Allow-Credentials: true
```
Vulnerable: Server echo back Origin tanpa whitelist validation.

**Pattern 2: Null Origin Lookup**
```http
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```
Vulnerable: Browser's sandbox origin (null) bisa digunakan.

**Pattern 3: Regex Bypass**
Jika server whitelist berdasarkan regex:
```
Allowed: .*\.target\.com
Vulnerable: attacker.com?.target.com (evil.com jadi pass regex)
```

**Pattern 4: Wildcard with Credentials**
```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
Invalid: Browser menolak wildcard + credentials. Tapi check dulu apakah server benar-benar send `*` atau ada logic berbeda.

### CSP Analysis Framework

Ketika melihat CSP header, parse setiap directive:

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self' https://trusted-cdn.com 'unsafe-inline';
  img-src 'self' data: https://*;
  connect-src 'self' https://api.target.com;
  frame-ancestors 'none';
  frame-src 'self';
  object-src 'none';
```

**Bypass vectors dari CSP lemah:**

1. `'unsafe-inline'` di script-src → XSS bisa jalan tanpa nonce/token
2. `'unsafe-eval'` di script-src → bisa eval() string sebagai code
3. Whitelist domain yang compromise-able (CDN, analytics, third-party JS)
4. `data:` di img-src → bisa inject base64 payload
5. `*` atau `https://*` di script-src → arbitrary JS bisa di-load
6. `frame-ancestors 'none'` missing → bisa di-iframe-kan untuk clickjacking

## Praktik Lab Legal

### Lab 1: JWT Decode, Modify & Re-sign

- **Nama lab:** JWT Token Manipulation
- **Tujuan:** Decode JWT, modifikasi claim, dan re-sign untuk privilege escalation
- **Environment:** Burp Suite, jwt.io, target lab dengan JWT auth (DVWA, Juice Shop, atau custom lab)
- **Langkah praktik:**

  1. Login ke target lab, capture JWT dari Authorization header atau cookie
  2. Decode JWT di jwt.io — identifikasi header, payload, signature
  3. Perhatikan claim: sub (user ID), role, exp, iss
  4. Modifikasi payload: ubah role dari "user" ke "admin", ubah sub ke user ID lain
  5. Di jwt.io, gunakan secret known untuk re-sign (misal: "secret" atau "password")
  6. Kirim modified JWT ke server, amati apakah request diterima
  7. Coba teknik lain:
     - Hapus signature (alg: none)
     - Ganti algorithm HS256 → none
     - Perpanjang exp claim
  8. Catat teknik mana yang berhasil dan jelaskan kenapa

- **Expected result:** Peserta bisa forge token dengan privilege lebih tinggi jika secret lemah atau validation flawed
- **Catatan keamanan:** Lab ini hanya untuk environment authorized. Jangan pernah crack JWT secret di target real tanpa izin.

### Lab 2: OAuth Flow Trace & State Parameter Testing

- **Nama lab:** OAuth Security Audit
- **Tujuan:** Trace OAuth flow dari authorize sampai callback, identifikasi missing state validation
- **Environment:** Browser dengan DevTools, Burp Suite, target aplikasi dengan OAuth integration (bisa menggunakan test OAuth app sendiri)
- **Langkah praktik:**

  1. Identifikasi aplikasi yang menggunakan OAuth (login dengan Google/GitHub/Facebook)
  2. Di Burp, aktifkan proxy dan clear cookies
  3. Klik login OAuth provider — capture semua request di Network/DevTools atau Burp
  4. Trace flow: authorization request → user consent → callback → token exchange
  5. Periksa setiap redirect URL untuk parameter `state`
  6. Jika state parameter ada: test apakah state di-bind ke session (logout, login lagi, gunakan state lama — apakah valid?)
  7. Jika state parameter tidak ada: ini adalah vulnerability OAuth CSRF
  8. Periksa redirect_uri untuk validation: apakah bisa redirect ke subdomain atau arbitrary domain?

- **Expected result:** Peserta bisa mendemonstrasikan OAuth flow dan identifikasi apakah state parameter digunakan dan divalidasi dengan benar
- **Catatan keamanan:** Hanya test aplikasi yang mengijinkan testing, atau buat OAuth app sendiri untuk latihan.

### Lab 3: CORS Misconfiguration Detection

- **Nama lab:** CORS Security Assessment
- **Tujuan:** Analisis CORS header dari target, identifikasi misconfiguration yang bisa diexploitasi
- **Environment:** Burp Suite, browser
- **Langkah praktik:**

  1. Browse ke target, intercept semua response via Burp
  2. Cari header `Access-Control-Allow-Origin` di setiap response
  3. Buat tabel semua CORS-enabled endpoint: URL, Origin policy, Credentials allowed, Methods
  4. Untuk setiap endpoint, test:
     - Origin arbitrary → apakah di-echo back?
     - Origin: null → apakah null di-allow?
     - Origin: evil.com → apakah diset sebagai allowed origin?
     - Credentials → apakah benar-benar bisa access dengan credentials?
  5. Jika credentials-enabled + arbitrary origin-accepted: buat PoC HTML yang fetch data dari victim's session
  6. Test preflight: kirim OPTIONS request dengan Origin header custom, lihat response

- **Expected result:** Peserta bisa membuat audit lengkap CORS configuration dan membuat PoC exploitation jika misconfiguration ditemukan
- **Catatan keamanan:** Lab ini bersifat observasional dan analisis. PoC exploitation tidak boleh dijalankan terhadap target real.

## Tools

- **JWT:** jwt.io (online debugger), Burp JWT Editor extension, python pyjwt library
- **OAuth:** Browser DevTools Network tab, Burp Suite
- **CORS:** Browser DevTools, Burp Suite, custom test page (HTML dengan fetch())
- **CSP:** Browser DevTools (Security tab), CSP Evaluator (Google)
- **Decoder:** Burp Decoder, CyberChef

## Checklist Bug Hunter

- [ ] Decode semua JWT yang ditemukan — periksa claim, algorithm, expiration
- [ ] Test apakah JWT accept `alg: none`
- [ ] Coba algorithm confusion: RS256 → HS256 dengan public key
- [ ] Modifikasi claim (sub, role, exp) dan test apakah server accept
- [ ] Identifikasi semua OAuth flow dan check apakah state parameter ada dan valid
- [ ] Check redirect_uri validation di OAuth flow
- [ ] Analisis semua CORS header — echo-back origin, wildcard with credentials, null origin
- [ ] Parse CSP header — identifikasi directive yang lemah (unsafe-inline, whitelist domain)
- [ ] Test apakah arbitrary Origin di-accept untuk credentials-enabled endpoint

## Common Mistakes

1. **JWT dilihat tapi tidak di-decode** — Researcher melihat token sebagai string panjang, tidak coba decode atau modifikasi. Ini adalah missed opportunity besar.

2. **Alg:none tidak ditest** — Karena `alg:none` dianggap "obviously vulnerable", researcher sering skip testing ini. Tapi ada server yang masih accept untuk compatibility reason.

3. **OAuth flow tidak di-trace sepenuhnya** — Researcher hanya lihat login button, tidak trace seluruh flow dari authorization sampai token exchange. State parameter check sering terlewat.

4. **CORS wildcard dianggap tidak useful** — Tanpa credentials, CORS wildcard memang tidak bisa exfiltrate data. Tapi banyak researcher miss pola echo-back origin yang bisa exploited.

5. **CSP dibaca tapi tidak di-interpretasi** — CSP yang terlihat "strict" sering memiliki bypass yang subtle via whitelisted CDN atau JSONP endpoint.

6. **Tidak test preflight request** — OPTIONS request handling sering berbeda dari GET/POST. CORS misconfiguration sering ada di preflight, bukan di actual request.

## Mitigasi Developer

**JWT:**
- Selalu specify expected algorithm di server-side validation — jangan accept semua algorithm
- Use strong, long random secrets for symmetric algorithm (HS256)
- Validate `aud` (audience) claim untuk memastikan token digunakan untuk service yang benar
- Implement token expiration dan rotation
- Jangan expose sensitive data di payload (payload adalah encoded, not encrypted)
- Use `jti` (JWT ID) claim untuk token revocation

**OAuth:**
- Selalu generate dan validate `state` parameter — bind ke user session
- Validate `redirect_uri` exactly, bukan dengan prefix matching
- Gunakan authorization code flow, bukan implicit flow
- Validasi setiap callback request server-side
- Implement PKCE untuk public clients

**CORS:**
- Whitelist specific origin, bukan wildcard atau regex yang bisa di-bypass
- Jangan gunakan `Access-Control-Allow-Credentials: true` dengan dynamic origin validation
- Validate Origin header secara server-side, bukan hanya cek existence
- Jika credentials diperlukan, origin harus spesifik dan validated

**CSP:**
- Remove `unsafe-inline` dan `unsafe-eval` dari script-src
- Use nonce atau hash-based CSP untuk script allowlist
- Jangan whitelist third-party domain yang tidak controlled penuh
- Set restrictive default-src policy
- Remove `data:` scheme dari directive kecuali benar-benar diperlukan

## Mini Quiz

1. JWT terdiri dari 3 bagian yang dipisahkan oleh titik. Bagian mana yang TIDAK di-encode secara default?
   a) Header
   b) Payload
   c) Signature
   d) Semua di-encode Base64URL

2. Jika server menerima JWT dengan algorithm "none" dan tidak memvalidasi algorithm dengan benar, attacker bisa:
   a) Decrypt payload
   b) Forge arbitrary token tanpa signature
   c) Mendapatkan secret key
   d) Decode semua JWT sebelumnya

3. OAuth state parameter berfungsi untuk:
   a) Menyimpan access token sementara
   b) CSRF protection di authorization flow
   c) Redirect user setelah authorization
   d) Validasi redirect_uri

4. CORS header `Access-Control-Allow-Origin: *` dengan `Access-Control-Allow-Credentials: true` akan:
   a) Berfungsi dengan benar
   b) Ditolak browser
   c) Mengijinkan semua origin dengan credentials
   d) Hanya work untuk subdomain

5. Header CSP `script-src 'self' https://cdn.example.com` berarti:
   a) Script hanya boleh dari origin yang sama dan cdn.example.com
   b) Script hanya dari cdn.example.com
   c) Semua script diijinkan
   d) Script diblokir semua

**Kunci Jawaban:** 1-C, 2-B, 3-B, 4-B, 5-A

## Assignment

1. **JWT Audit:** Cari 3 web app berbeda yang menggunakan JWT untuk auth (bisa lab atau public site yang disclose ini). Decode setiap JWT yang ditemukan. Identifikasi: algorithm, claims, weakness. Buat laporan per JWT.

2. **OAuth Flow Mapping:** Identifikasi 2 aplikasi yang menggunakan OAuth (Google/GitHub login). Trace entire flow dan dokumentasikan: redirect_uri, state parameter, scope, callback handling. Analisis apakah ada kelemahan.

3. **CORS + CSP Analysis:** Pilih 5 endpoint/API dari hasil recon yang berbeda. Analisis CORS configuration dan CSP header untuk setiap endpoint. Buat risk matrix berdasarkan temuan.

4. **JWT Manipulation Challenge:** Gunakan lab target yang diketahui weak secret (misal: Juice Shop). Attempt privilege escalation via JWT manipulation (modifikasi role dari "customer" ke "admin"). Document setiap teknik yang dicoba dan hasilnya.

## Template Report Bug Bounty

```markdown
# Bug Report: JWT Algorithm Confusion Leading to Privilege Escalation

## Summary
Endpoint /api/profile mengijinkan JWT dengan algorithm HS256 tanpa validasi
yang tepat. Attacker bisa forge admin token dengan menggunakan public key
sebagai HMAC secret.

## Platform / Program
HackerOne | [Program Name]

## Severity
Critical | CVSS 9.0 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Vulnerability Type
Authentication Bypass / JWT Algorithm Confusion

## Asset / Endpoint
https://api.target.com/api/profile

## Description
Server menggunakan JWT untuk autentikasi. Ketika request diterima,
server tidak memvalidasi bahwa algorithm yang digunakan match dengan yang
diharapkan (RS256). Server menggunakan public key (yang seharusnya untuk
RS256 verification) sebagai symmetric secret untuk HS256 verification.
Attacker memanfaatkan ini dengan:
1. Mengambil public key dari /api/auth/keys
2. Membuat JWT baru dengan header {"alg":"HS256"}
3. Sign JWT menggunakan public key sebagai secret
4. Kirim forged token untuk privilege escalation

## Steps to Reproduce
1. Register account biasa: user@test.com
2. Login, capture JWT dari Authorization header
   JWT: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
3. Decode JWT, lihat payload: {"sub":"123","email":"user@test.com","role":"user",...}
4. Ambil public key dari GET https://api.target.com/api/auth/keys
5. Buat JWT baru dengan payload {"sub":"123","email":"user@test.com","role":"admin","exp":9999999999}
   Header: {"alg":"HS256","typ":"JWT"}
   Signature: HMAC-SHA256(header.payload, public_key)
6. Kirim request dengan modified JWT di Authorization header
7. Server accept token dan memberikan akses admin

## Impact
- Full account takeover: attacker bisa access semua user data
- Privilege escalation: regular user bisa gain admin access
- Data manipulation: admin access memungkinkan modify/delete data
- severity: Critical — ini memberikan kontrol penuh atas aplikasi

## Evidence
[Burp Screenshot: Original JWT decoded di jwt.io]
[Burp Screenshot: Modified JWT dengan role=admin]
[Burp Screenshot: Response dengan elevated privileges]
[Burp Screenshot: Request/Response showing admin access]

## Remediation / Recommendation
1. Selalu specify expected algorithm di server validation
2. Tolak algorithm "none" secara eksplisit
3. Validasi algorithm match: hanya accept RS256 untuk public key verification
4. Implementasi JWT ID (jti) claim untuk token revocation
5. Rotate signing keys secara berkala
```

---

*Module ini adalah landasan critical. Researcher yang tidak paham JWT, OAuth, CORS, dan CSP akan miss vulnerability yang paling sering dibayar di platform bug bounty manapun.*