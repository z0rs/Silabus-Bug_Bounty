# Sesi 15 — Business Logic Vulnerabilities

> **Level:** Intermediate–Advanced  
> **Durasi Estimasi:** 4–5 jam (teori + case study)  
> **Prasyarat:** Sesi 02 (HTTP), Sesi 06 (Auth), Sesi 07 (IDOR)  
> **Tools:** Burp Suite, Browser DevTools, Postman

---

## 🎯 Tujuan Pembelajaran

Setelah menyelesaikan sesi ini, peserta mampu:
- Memahami apa yang membedakan business logic bug dari bug teknikal lainnya
- Mengidentifikasi pola business logic yang sering rentan
- Menguji workflow multi-step untuk state machine bypass
- Menemukan price/quantity manipulation di e-commerce
- Mengeksploitasi flow bypass di proses yang mestinya sequential
- Membuat laporan business logic yang persuasif dengan impact bisnis nyata

---

## 📚 Bagian 1 — Memahami Business Logic Bugs

### 1.1 Apa yang Membedakan Business Logic Bug?

```
Bug Teknikal (SQL Injection, XSS):
→ Ada di semua aplikasi yang menggunakan teknologi sama
→ Bisa di-scan dengan tools otomatis
→ Ada CVE / payload database yang bisa digunakan

Business Logic Bug:
→ Spesifik ke aplikasi dan model bisnis tertentu
→ Tidak bisa di-detect oleh scanner otomatis
→ Membutuhkan pemahaman tentang "bagaimana app seharusnya bekerja"
→ Developer tidak memikirkan skenario "apa yang terjadi jika user...?"
```

### 1.2 Mindset untuk Hunting Business Logic

```
Pertanyaan yang harus selalu ditanyakan:

"Apa yang terjadi jika user..."
→ ...mengirim request step 3 sebelum step 1?
→ ...menggunakan negative value sebagai quantity?
→ ...mengirim dua request yang sama secara bersamaan?
→ ...melewati halaman konfirmasi dan langsung ke endpoint final?
→ ...menggunakan fitur dalam urutan yang tidak normal?
→ ...memasukkan data yang secara teknis valid tapi secara bisnis tidak masuk akal?
→ ...menggabungkan dua fitur yang seharusnya tidak digabungkan?
```

### 1.3 Kategori Business Logic Bug

```
1. EXCESSIVE TRUST IN CLIENT-SIDE VALIDATION
   → Harga, diskon, quantity dikirim dari client dan dipercaya server

2. FLAWED ASSUMPTION ABOUT USER INPUT
   → Asumsi: user tidak akan input angka negatif
   → Asumsi: user tidak akan memanipulasi hidden fields

3. WORKFLOW/STATE MACHINE BYPASS
   → Multi-step process tidak di-enforce di server
   → Bisa skip step atau replay step sebelumnya

4. DOMAIN-SPECIFIC LOGIC FLAWS
   → Discount stacking yang tidak dibatasi
   → Transfer ke diri sendiri
   → Referral abuse

5. INCONSISTENT VALIDATION
   → Validasi ada di satu endpoint tapi tidak di endpoint lain
   → Validasi berbeda di API vs web UI
```

---

## 📚 Bagian 2 — Price & Quantity Manipulation

### 2.1 Harga Dikirim dari Client

```http
# Banyak aplikasi e-commerce mengirim harga dari form HTML
# atau dalam request body dan mempercayai nilainya

# Request normal checkout
POST /api/cart/checkout HTTP/1.1
Content-Type: application/json

{
  "items": [
    {
      "product_id": "MACBOOK-PRO-2024",
      "quantity": 1,
      "price": 25000000   ← apakah server validasi ini dari DB?
    }
  ]
}

# Manipulasi: ubah harga
{
  "items": [
    {
      "product_id": "MACBOOK-PRO-2024",
      "quantity": 1,
      "price": 1          ← ubah harga ke Rp 1!
    }
  ]
}

# Jika server hanya pakai harga dari request → beli MacBook seharga Rp 1!
```

### 2.2 Negative Quantity / Price

```http
# Test: quantity negatif
{
  "items": [
    {"product_id": "ITEM-001", "quantity": -1, "price": 100000}
  ]
}
# Jika diproses: total = -100000 → beli produk, saldo BERTAMBAH?

# Test: harga negatif
{
  "items": [
    {"product_id": "ITEM-001", "quantity": 1, "price": -100000}
  ]
}

# Test: kombinasi (satu item harga positif, satu negatif)
{
  "items": [
    {"product_id": "ITEM-001", "quantity": 1, "price": 500000},
    {"product_id": "ITEM-002", "quantity": 1, "price": -499999}  ← negatif
  ]
}
# Total: Rp 1 → beli dua produk seharga Rp 1
```

### 2.3 Coupon/Discount Abuse

```http
# Test 1: Apply coupon berkali-kali
POST /api/cart/apply-coupon {"code": "SAVE50"} → 50% off
POST /api/cart/apply-coupon {"code": "SAVE50"} → 50% lagi?

# Test 2: Multiple coupon stacking
POST /api/cart/apply-coupon {"code": "SAVE50"}  → 50%
POST /api/cart/apply-coupon {"code": "SAVE20"}  → 50% + 20%?

# Test 3: Coupon setelah checkout (refund race)
1. Add item → Apply coupon → Checkout
2. Request refund
3. Apply coupon lagi untuk order baru
→ Apakah coupon bisa digunakan setelah refund?

# Test 4: Coupon pada item yang exclude
# Coupon "tidak berlaku untuk elektronik" → test pada elektronik
# Mungkin validasi hanya di frontend (JavaScript)
```

---

## 📚 Bagian 3 — Workflow / Multi-Step Process Bypass

### 3.1 Parameter Manipulation di Multi-Step

```
Typical multi-step checkout:
Step 1: /checkout/cart → review items
Step 2: /checkout/shipping → pilih alamat
Step 3: /checkout/payment → masukkan payment
Step 4: /checkout/confirm → konfirmasi
Step 5: /checkout/complete → order dibuat

Bypass tests:
1. Akses step 5 langsung tanpa step sebelumnya
2. Ubah parameter di step 3 yang di-set di step 2
3. Replay step 3 dengan data berbeda setelah step 4
```

```http
# Step 1: Review cart (server kirim cart_token)
GET /checkout/cart HTTP/1.1
→ Response: {"cart_token": "abc123", "total": 5000000}

# Step 2: Shipping
POST /checkout/shipping HTTP/1.1
{"cart_token": "abc123", "address_id": "ADDR-001"}

# Step 3: Payment method dipilih
POST /checkout/payment HTTP/1.1
{"cart_token": "abc123", "payment_method": "credit_card"}
→ Server set total yang akan dicharge

# ATTACK: Sebelum step 4, modifikasi cart
# Hapus item mahal dari cart
DELETE /api/cart/item/EXPENSIVE-ITEM

# Step 4: Confirm (server masih pakai total dari step 3?)
POST /checkout/confirm HTTP/1.1
{"cart_token": "abc123"}

# Step 5: Order dibuat dengan harga lama tapi item sudah diubah!
```

### 3.2 State Machine Bypass

```
Email verification bypass:

Normal flow:
1. Register → email terkirim → klik link verifikasi → akun aktif
2. Login → hanya bisa akses limited features sampai verifikasi

Bypass: setelah register, langsung akses endpoint yang butuh verified account
GET /api/user/dashboard → harusnya redirect ke "verify email"
# Apakah server cek is_verified di setiap endpoint?
# Atau hanya cek di beberapa endpoint?

# Test: request API endpoint langsung setelah register (tanpa verify)
GET /api/user/data HTTP/1.1
Authorization: Bearer [TOKEN_DARI_UNVERIFIED_ACCOUNT]
```

### 3.3 Exploiting Inconsistent Validation

```
Skenario: Aplikasi punya dua cara untuk melakukan aksi yang sama
1. Via Web UI (banyak validasi JavaScript)
2. Via API endpoint (validasi lebih sedikit)

Test: lakukan aksi via API endpoint dengan data yang ditolak di UI

Contoh:
UI: "Transfer minimum Rp 10.000"
API: POST /api/transfer {"amount": 1} → apakah ada validasi di sisi server?

UI: "Username hanya boleh alphanumeric"
API: POST /api/user/register {"username": "<script>alert(1)</script>"}
→ Username disimpan → stored XSS saat admin lihat user list!
```

---

## 📚 Bagian 4 — Feature Interaction Bugs

### 4.1 Password Reset + Account Takeover Chain

```
Bug: Registrasi email yang di-normalize berbeda dengan reset password

Skenario:
1. Victim punya akun: victim@gmail.com
2. Attacker coba daftar: victim@gmail.com → "email sudah digunakan"
3. Attacker daftar: Victim@Gmail.Com (uppercase)
   → Server normalize saat simpan: victim@gmail.com
   → Tapi karena kasus berbeda, dianggap sebagai akun baru
   → Akun baru dibuat!
4. Attacker request reset password untuk Victim@Gmail.Com
   → Email terkirim ke victim@gmail.com (pemilik asli)
   → Tapi link reset berlaku untuk akun Attacker!
5. Victim klik link → password Victim di-reset milik Attacker
→ ATO!
```

### 4.2 Race Condition pada Transfer/Transaction

```python
# Skenario: Double-spend via concurrent requests
# Balance: Rp 100.000
# Transfer Rp 100.000 ke dua akun berbeda secara bersamaan

import threading
import requests

def transfer(to_account):
    return requests.post('https://target.com/api/transfer', 
                        json={
                            "to": to_account, 
                            "amount": 100000
                        },
                        headers={"Authorization": f"Bearer {TOKEN}"})

# Kirim dua transfer bersamaan
t1 = threading.Thread(target=transfer, args=("ACCOUNT_A",))
t2 = threading.Thread(target=transfer, args=("ACCOUNT_B",))

t1.start()
t2.start()
t1.join()
t2.join()

# Jika server tidak pakai transaction/lock:
# Keduanya mungkin berhasil → transfer Rp 200.000 dari Rp 100.000!
```

### 4.3 Referral System Abuse

```
Bugs umum di referral/affiliate system:

1. SELF-REFERRAL:
   Register akun A → generate referral code
   Register akun B menggunakan referral code A → keduanya dapat reward
   Masalah: attacker bisa buat unlimited akun

2. CIRCULAR REFERRAL:
   A refer B → B refer C → C refer A
   Infinite reward loop jika tidak dicek

3. RETROACTIVE REFERRAL:
   Register dulu tanpa referral
   Kemudian apply referral code → masih dapat reward?

4. REFERRAL BEFORE FIRST PURCHASE:
   Gunakan referral code untuk account yang belum pernah purchase
   Ubah email setelah menggunakan → bypass "baru pernah purchase" check
```

---

## 📚 Bagian 5 — Metodologi Testing Business Logic

### 5.1 Framework: "What If" Analysis

```
Untuk setiap fitur, tanyakan:

BOUNDARY TESTS:
□ Apa yang terjadi dengan nilai 0?
□ Nilai negatif?
□ Nilai sangat besar (integer overflow)?
□ Nilai desimal yang tidak diharapkan (0.001)?
□ String di field numerik?
□ Array di field yang harusnya single value?

SEQUENCE TESTS:
□ Bisa akses step N+1 tanpa step N?
□ Bisa ulang step yang sudah selesai?
□ Bisa kembali ke step sebelumnya?
□ Bisa kombinasi step dari workflow berbeda?

ROLE TESTS:
□ Aksi yang dibuat sebagai role A, dikonsumsi sebagai role B?
□ Upgrade/downgrade akun mid-workflow?
□ Share resource antara user berbeda?

TIMING TESTS:
□ Aksi sebelum pembayaran dikonfirmasi?
□ Dua request bersamaan (race condition)?
□ Aksi setelah expiry?
```

### 5.2 Membaca Application Flow dengan Burp

```
Cara trace business logic di Burp:

1. Buka Burp → Proxy → HTTP History
2. Lakukan satu workflow lengkap (misal: checkout)
3. Filter history → lihat urutan request
4. Identifikasi:
   - Parameter yang muncul berulang kali (token, ID)
   - Response yang mengandung state (confirmed, pending, failed)
   - Redirect yang bisa di-skip

5. Coba variasi:
   - Replay request dengan nilai berbeda
   - Kirim request out-of-order
   - Manipulasi parameter state
```

---

## 🔴 Real Bug Bounty Cases

### Case 1 — Price Manipulation di Shopify (Real Pattern)

> **Platform:** HackerOne — Shopify dan e-commerce programs  
> **Referensi:** Pola umum dari e-commerce bug bounty reports  
> **Severity:** High (P2)

**Skenario:**
Shopify merchant app mengizinkan customisasi harga melalui draft order API. Peneliti menemukan bahwa harga bisa di-set ke nilai 0 atau negatif melalui API call yang tidak di-validasi server.

```http
# API untuk buat draft order
POST /admin/api/2024-01/draft_orders.json HTTP/1.1
Host: merchant.myshopify.com

{
  "draft_order": {
    "line_items": [{
      "variant_id": 12345,
      "quantity": 1,
      "price": "0.00"   ← harga di-override ke Rp 0!
    }]
  }
}
# Response: Draft order dibuat dengan harga Rp 0!
# Invoice dikirim ke customer dengan harga Rp 0
```

---

### Case 2 — Coupon Code Infinite Reuse di E-commerce Platform (Pattern)

> **Referensi:** Pola umum dari bug bounty reports tentang coupon abuse  
> **Severity:** High — direct financial impact

**Skenario:**
Platform e-commerce mengizinkan coupon "satu kali pakai per user" tetapi validasi dilakukan berdasarkan `user_id` di request body (client-controlled) bukan session.

```http
# Request dengan user_id dari cookie/session → coupon dipakai
POST /api/coupon/apply HTTP/1.1
Cookie: session=USER_A_SESSION

{"coupon_code": "DISC50", "user_id": "USER_A"}  ← server trust ini

# Bypass: ganti user_id ke string berbeda
{"coupon_code": "DISC50", "user_id": "USER_A_2"} ← dianggap user berbeda!
{"coupon_code": "DISC50", "user_id": "user_a"}   ← lowercase dianggap baru
{"coupon_code": "DISC50", "user_id": "USER_A "}  ← trailing space

# Setiap variasi = satu pemakaian coupon baru!
```

---

### Case 3 — Free Premium Upgrade via Downgrade Race (Real Pattern)

> **Referensi:** Terinspirasi dari pola race condition pada subscription management  
> **Severity:** Medium–High

**Skenario:**
Platform SaaS menawarkan trial premium gratis 7 hari. Peneliti menemukan:

1. Upgrade ke premium → fitur aktif
2. Selama premium: download semua resources, export data
3. Downgrade sebelum billing cycle → tidak kena charge

Yang lebih menarik:
```
Bug: Race condition saat periode trial berakhir

Ketika trial akan expired dalam 1 menit:
→ Thread 1: terus gunakan premium features (belum expired)
→ Thread 2: request yang membutuhkan premium features secara rapid
→ Window antara "expired" di timer dan "check di server" → dapat fitur gratis!
```

---

### Case 4 — Negative Balance via Transfer Manipulation (Real — Banking App Pattern)

> **Referensi:** Pola dari financial application bug bounty reports  
> **Severity:** Critical

**Skenario:**
Aplikasi dompet digital mengizinkan transfer ke sesama user. Peneliti menemukan:

```http
# Transfer normal
POST /api/wallet/transfer HTTP/1.1
{"to": "USER_B", "amount": 100000}

# Test: transfer ke diri sendiri
POST /api/wallet/transfer HTTP/1.1
{"to": "USER_A", "amount": 100000}  ← USER_A adalah pengirim!
# Apakah balance berkurang? Bertambah? Tidak berubah?

# Test lebih jauh: transfer dengan jumlah > balance
POST /api/wallet/transfer HTTP/1.1
{"to": "USER_B", "amount": 999999999}  ← jauh lebih besar dari balance!
# Apakah ada validasi? Atau bisa negative balance?
```

---

## 🛠️ Lab Praktik

### Lab 1 — PortSwigger Web Academy Business Logic Labs (Gratis)
- 🔗 [Excessive trust in client-side controls](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls)
- 🔗 [High-level logic vulnerability](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-high-level)
- 🔗 [Low-level logic flaw (integer overflow)](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-low-level)
- 🔗 [All Business Logic Labs](https://portswigger.net/web-security/logic-flaws)

### Lab 2 — OWASP Juice Shop
```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
# Challenges yang relevan:
# - "Manipulate the basket to get a product for free"
# - "Obtain a 92.5% discount"
# - "Apply expired coupon"
# - "Place an order that makes you rich" (negative price)
```

### Lab 3 — HackTheBox Academy
- 🔗 [Web Attacks — Business Logic section](https://academy.hackthebox.com/module/details/134)

### Lab 4 — TryHackMe
- 🔗 [OWASP Top 10 2021 — Insecure Design](https://tryhackme.com/room/owasptop102021)

---

## 📋 Business Logic Testing Checklist

```markdown
## Business Logic Checklist

### Price / Quantity
- [ ] Harga dikirim dari client → manipulasi ke 0/negatif?
- [ ] Quantity negatif?
- [ ] Integer overflow (MAX_INT)?
- [ ] Diskon/coupon bisa dipakai berkali-kali?
- [ ] Multiple coupon stacking?

### Workflow / State
- [ ] Bisa skip step dalam multi-step process?
- [ ] Bisa replay step yang sudah selesai?
- [ ] Parameter state bisa dimanipulasi di client?
- [ ] Direct endpoint access tanpa setup yang benar?

### Boundary
- [ ] Transfer ke diri sendiri?
- [ ] Amount > balance?
- [ ] Aksi setelah resource deleted/expired?
- [ ] Concurrent requests (race condition)?

### Feature Interaction
- [ ] Email normalization issues?
- [ ] Referral self-use?
- [ ] UI validation vs API validation sama?
- [ ] Role change mid-workflow?
```

---

## 📖 Referensi & Bacaan Lanjutan

| Sumber | Link | Topik |
|--------|------|-------|
| PortSwigger | [Business Logic Vulnerabilities](https://portswigger.net/web-security/logic-flaws) | Complete guide |
| OWASP | [Testing for Business Logic Errors](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/) | Testing methodology |
| James Kettle | [Hunting Evasive Vulnerabilities](https://portswigger.net/research/hunting-evasive-vulnerabilities) | Advanced research |
| HackerOne | [Business Logic Reports](https://hackerone.com/hacktivity?querystring=business+logic) | Real examples |
| OWASP Juice Shop | [Vulnerability Guide](https://pwning.owasp-juice.shop/) | Practical challenges |

---

## 🔑 Key Takeaways

1. **Business logic bugs butuh pemahaman bisnis** — baca fitur dengan mindset "bagaimana saya bisa salahgunakan ini?"
2. **Client-side validation = tidak ada validasi** — semua yang dikirim dari browser bisa dimanipulasi
3. **Multi-step process adalah goldmine** — banyak developer tidak enforce urutan di server
4. **Impact bisnis harus jelas** — laporan "harga bisa dimanipulasi menjadi Rp 0" lebih convincing dari "parameter tidak divalidasi"
5. **Interaksi fitur yang tidak terduga** — gabungkan fitur A dan fitur B untuk temukan bug yang developer tidak antisipasi

---

*Sesi berikutnya: **Sesi 21 — OAuth, JWT & CORS/WebSocket***
