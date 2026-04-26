# IDOR, BOLA & Broken Access Control

## Fokus Materi

Mengidentifikasi dan mengeksploitasi broken access control vulnerabilities — salah satu kelas bug paling umum di bug bounty modern, terutama dengan shift ke REST API. IDOR (Insecure Direct Object Reference) dan BOLA (Broken Object Level Authorization) adalah entry point untuk privilege escalation dan data breach.

## Deskripsi Materi

Access control adalah aturan yang menentukan siapa boleh akses apa. Ketika aturan ini tidak diimplementasikan dengan benar, attacker bisa mengakses data atau fungsi yang seharusnya tidak boleh mereka akses — tanpa perlu exploit 技术 yang canggih.

IDOR terjadi ketika aplikasi menggunakan user-supplied input untuk direct access ke object tanpa authorization check. Contoh klasik: URL seperti `/api/orders/12345` — attacker ganti 12345 ke 12346 dan bisa lihat orders user lain. Ini adalah vulnerability yang sederhana tapi impact-nya bisa sangat besar.

BOLA adalah istilah yang digunakan OWASP API Security Top 10 untuk describe IDOR di konteks API. Di API, akses ke object biasanya dilakukan via ID di path, query parameter, atau request body. Jika authorization check tidak dilakukan untuk setiap request, attacker bisa enumerate dan akses object yang bukan miliknya.

BFAC (Broken Function Level Access Control) terjadi ketika aplikasi tidak properly restrict akses ke fungsi tertentu. Misalnya: endpoint `/api/admin/users` yang seharusnya hanya accessible oleh admin tapi accessible oleh semua authenticated user. Atau fungsi DELETE/PUT yang seharusnya require higher privilege.

Horizontal vs Vertical Privilege Escalation:
- Horizontal: Akses ke resource user lain di level yang sama (user A lihat data user B)
- Vertical: Akses ke resource/function di level privilege yang lebih tinggi (regular user akses admin function)

Autorize Burp extension adalah tool standar untuk testing access control secara systematic. Dengan intercepting request dari 2 different roles (user dan admin), researcher bisa automatically compare responses dan identify access control gaps.

## Topik Pembahasan

• IDOR fundamentals: bagaimana server tidak memvalidasi kepemilikan resource sebelum give access
• IDOR types: path parameter (/user/1234), query string (?id=), request body (JSON body field), response leakage
• BOLA di REST API: ganti ID di setiap endpoint — path, query, body
• BFAC: akses fungsi admin/privileged tanpa authorization
• Horizontal vs vertical privilege escalation: perbedaan dan cara identifikasi
• Autorize Burp extension: setup, intercepting request dua role berbeda, result interpretation
• Mass testing IDOR: teknik otomasi intercept + replace ID dengan Autorize + Intruder
• Access control mapping: dari hasil recon ke authorization test plan
• CVSS scoring untuk access control: scope, attack complexity, privileges required
• Impact statement untuk access control bug: business impact beyond technical detail

## Tujuan Pembelajaran

Setelah sesi ini, peserta diharapkan mampu:
1. Identifikasi IDOR pattern di berbagai context (path, query, body)
2. Melakukan systematic access control testing menggunakan Autorize
3. Melakukan horizontal privilege escalation testing
4. Melakukan vertical privilege escalation testing
5. Memahami perbedaan IDOR, BOLA, dan BFAC
6. Automate IDOR testing dengan Burp Intruder dan custom scripts
7. Menulis access control bug report dengan impact yang convincing

## Real Case Bug Bounty Report

- Platform: HackerOne
- Program/Target: Private program (disclosed researcher writeup)
- Jenis vulnerability: BOLA/IDOR memungkinkan horizontal data access di API
- Link report: https://hackerone.com/reports/XXXXX
- Ringkasan kasus: Researcher menguji endpoint GET /api/v1/user/profile/{id}. Dengan mengganti {id} ke user ID lain, researcher bisa melihat complete profile user lain — termasuk email, phone, address, dan partial payment info. Tidak ada authorization check di endpoint tersebut; server hanya verify bahwa requester adalah authenticated user, bukan bahwa requester boleh access target user's data.
- Root cause: API endpoint tidak implement authorization check untuk ownership. Hanya check user is authenticated (valid token), tidak check if user has permission untuk access resource with specific ID.
- Impact: Full profile data dari all users bisa diakses. Privacy breach dari seluruh user base. Severity: High (CVSS 7.5)
- Pelajaran untuk bug hunter: Selalu test semua ID-type parameter dengan other user IDs. Authentication ≠ authorization.

---

- Platform: Bugcrowd
- Program/Target: Social media platform
- Jenis vulnerability: BFAC — regular user bisa execute admin functions
- Link report: Disclosed writeup
- Ringkasan kasus: Researcher menemukan bahwa endpoint POST /api/admin/users/{id}/role hanya check apakah user adalah authenticated, tidak check apakah user memiliki admin role. Regular user dengan valid token bisa call endpoint ini untuk promote themselves atau other user ke admin. Endpoint seharusnya return 403 Forbidden untuk non-admin, tapi return 200 OK dan apply change.
- Root cause: Authorization middleware tidak applied ke admin endpoint. Developer assumed that admin endpoints will only be called from admin interface, without server-side authorization check.
- Impact: Regular user bisa escalasi ke admin privilege → full application takeover. Severity: Critical.
- Pelajaran untuk bug hunter: Test semua endpoints yang looks like admin functions — bahkan jika they're not linked in the UI.

## Analisis Teknis

### IDOR Attack Patterns

**Pattern 1: Path Parameter**
```
# Legitimate: User A access their own order
GET /api/orders/10045 HTTP/1.1
Authorization: Bearer token_user_a

# Attack: User A access User B's order
GET /api/orders/10046 HTTP/1.1
Authorization: Bearer token_user_a
```

Response:
- If vulnerable: HTTP 200 + {"order_id":10046,"user_id":"user_b",...}
- If not vulnerable: HTTP 403 Forbidden

**Pattern 2: Query String Parameter**
```
# Legitimate
GET /api/invoices?id=10045 HTTP/1.1

# Attack
GET /api/invoices?id=10046 HTTP/1.1
```

**Pattern 3: Request Body (JSON)**
```json
# Request dengan embedded ID
POST /api/transfer HTTP/1.1
{"from_account":"12345","to_account":"67890","amount":100}

# Attack: change from_account
{"from_account":"12346","to_account":"67890","amount":100}
```

**Pattern 4: Response-Driven IDOR**
```http
# API returns list dengan IDs
GET /api/friends HTTP/1.1
Response: [{"id":100,"name":"John"}, {"id":101,"name":"Jane"}]

# Attacker then access individual profile
GET /api/friends/100 HTTP/1.1
GET /api/friends/101 HTTP/1.1
```

**Pattern 5: Mass Assignment IDOR**
```json
# API accepts additional fields via mass assignment
POST /api/profile HTTP/1.1
{"name":"John","email":"john@example.com","role":"admin"}
```

### Autorize Burp Extension Setup & Workflow

**Installation:**
1. Open Burp → Extender → BApp Store
2. Search "Autorize" → Install
3. Extensions tab → Autorize akan muncul

**Configuration:**
1. Open Autorize tab
2. Set "Intercept requests from" ke browser (proxy scope)
3. Configure "Request to test": use original token atau low-privilege token
4. Set "Request to send": use high-privilege token (admin)
5. Enable "Auto-add headers from cookie of unfiltered requests"

**Workflow:**
1. Login sebagai Low Privilege User (User A)
2. Browse through application → Autorize auto-intercept
3. In separate browser: Login sebagai High Privilege User (Admin)
4. Copy Admin cookie/session
5. In Autorize, paste admin session
6. Continue browsing as User A → Autorize replace token dan send as Admin
7. Compare responses:
   - Unfiltered (low privilege): original response
   - Filtered disabled: response with high privilege token (to compare)
   - Filtered enabled: response if access control exists

**Result Interpretation:**
| Unfiltered | Filtered Enabled | Filtered Disabled | Interpretation |
|-----------|------------------|-------------------|----------------|
| 200 | 200 | 200 | Access control NOT implemented |
| 200 | 403 | 403 | Access control properly implemented |
| 200 | 200 | 403 | Access control partially implemented |
| 200 | 403 | 200 | Anomaly — check manually |

### Mass IDOR Testing dengan Intruder

```bash
# Step 1: Collect IDs from legitimate access
# Browse as User A, note all IDs accessible:
# GET /api/documents/1001
# GET /api/documents/1002
# etc.

# Step 2: Send to Intruder
# Capture one request → Send to Intruder
# PUT /api/documents/1001 HTTP/1.1
# Change ID to payload position

# Step 3: Load ID list as payload
# Generate list: 1001, 1002, 1003... (both known and guess)
# Or enumerate sequentially

# Step 4: Analyze response untuk each ID
# Success pattern: 200 OK with data
# Failure pattern: 403 Forbidden or 404 Not Found
```

**Automation Script (Burp Intruder + Grep):**
```
Payload list: sequential numbers 1000-9999
Grep pattern: "user_id" or "account_number" — indicate successful access
Filter: status code + response length variance
```

### Horizontal vs Vertical Escalation

**Horizontal Privilege Escalation:**
```
User A (user_id=100) accesses:
- User B's profile (user_id=101) via GET /api/users/101
- User B's orders via GET /api/orders?user_id=101
- User B's files via GET /api/files/500 (owned by user 101)

Both users have same privilege level (regular user).
Access to other user's resource = horizontal escalation.
```

**Vertical Privilege Escalation:**
```
Regular User accesses:
- Admin panel via GET /api/admin/users
- Admin function via POST /api/admin/ban?user_id=101
- Elevated function via PUT /api/settings (privileged action)

Regular User → Admin functionality = vertical escalation.
```

**Testing Strategy:**
1. As regular user, identify all functionality (endpoints)
2. Attempt each functionality with regular user token
3. For each endpoint, check if action succeeds beyond what regular user should access
4. Categorize: horizontal (user-to-user) vs vertical (role escalation)

## Praktik Lab Legal

### Lab 1: IDOR Discovery & Exploitation

- **Nama lab:** IDOR Attack Chain
- **Tujuan:** Find dan exploit IDOR untuk horizontal privilege escalation
- **Environment:** Burp Suite, Autorize extension, target lab dengan multiple user accounts (DVWA, Juice Shop, atau lab custom)
- **Langkah praktik:**

  1. Create 2 accounts: User A dan User B
  2. Login sebagai User A, identify all endpoints yang access user-specific data
  3. For each endpoint, note ID parameter (path, query, body)
  4. Login sebagai User B, capture User B's IDs
  5. As User A, attempt access User B's resource using User B's IDs
  6. Document: which endpoints vulnerable, which properly protected
  7. Analyze response untuk sensitive data exfiltration

- **Expected result:** Peserta menemukan minimal 3 IDOR vulnerabilities dengan varying severity
- **Catatan keamanan:** Lab ini untuk authorized testing environment. IDOR testing di target real harus dalam scope program.

### Lab 2: BOLA Testing dengan Autorize

- **Nama lab:** API Access Control Audit
- **Tujuan:** Systematic access control testing menggunakan Autorize extension
- **Environment:** Burp Suite + Autorize, Postman/Insomnia, target lab dengan API
- **Langkah praktik:**

  1. Setup Autorize dengan low privilege token (regular user)
  2. Paste high privilege token (admin) di Autorize configuration
  3. Browse entire application as regular user — Autorize automatically tests each request with admin token
  4. Review Autorize results: focus on "Authorization Bypass Detected"
  5. For each detected, manually verify: is it true positive atau false positive?
  6. Document all confirmed access control bypass

- **Expected result:** Peserta membuat audit lengkap access control vulnerabilities menggunakan automated approach
- **Catatan keamanan:** Hanya gunakan di environment authorized.

### Lab 3: Vertical Privilege Escalation

- **Nama lab:** Admin Function Access
- **Tujuan:** Test apakah regular user bisa akses admin functionality
- **Environment:** Burp Suite, browser dengan 2 role (regular + admin)
- **Langkah praktik:**

  1. Login sebagai Admin, map all admin endpoints (user management, system settings, etc.)
  2. Logout, login sebagai Regular User
  3. Attempt to access each admin endpoint dengan regular user token
  4. Document: which endpoints accessible, which properly blocked
  5. For accessible admin functions, test capability:
     - Could regular user delete other users?
     - Could regular user change role?
     - Could regular user access admin panel?
  6. Create PoC untuk highest impact finding

- **Expected result:** Peserta menemukan minimal 1 vertical privilege escalation dengan admin capability
- **Catatan keamanan:** Lab ini hanya untuk authorized testing.

## Tools

- **Access control testing:** Burp Suite Professional (Autorize extension), manual intercept + compare
- **API testing:** Postman, Insomnia, Burp Repeater
- **ID enumeration:** Burp Intruder, ffuf (for parameter fuzzing)
- **Session management:** Browser with multiple profiles/incognito windows
- **Analysis:** JSON parser (jq), diff tools for response comparison

## Checklist Bug Hunter

- [ ] Identify all endpoints yang accept ID parameter (path, query, body)
- [ ] Test horizontal escalation: access other user's resource dengan your token
- [ ] Test vertical escalation: access admin/superadmin function dengan regular token
- [ ] Setup Autorize dan run systematic access control audit
- [ ] Test mass assignment untuk IDOR (additional fields in body)
- [ ] Test response-driven IDOR (enumerate IDs from list endpoint)
- [ ] Check untuk IDOR in file access (document, image, attachment download)
- [ ] Test IDOR in state-changing operations (PUT, DELETE, POST)
- [ ] Verify each finding dengan second account confirmation
- [ ] Document access control gaps dengan clear impact statement

## Common Mistakes

1. **Only test own resources** — Researcher hanya test their own data, tidak mencoba access other user's resources. IDOR often missed because researcher tidak enumerate other IDs.

2. **Not testing admin endpoints from regular user** — Researcher only browse as admin, tidak try to access admin endpoints sebagai regular user. Many apps have authorization check missing for backend API even if UI blocks it.

3. **Report without authorization context** — IDOR report tanpa show that attacker could access OTHERS' data will get low severity. Always show comparison with another user's data.

4. **Skip mass testing** — Manual testing of each ID endpoint satu-per-satu inefficient. Use Autorize or Intruder untuk mass testing.

5. **Not checking state-changing IDOR** — Researcher only test read operations (GET), miss write operations (PUT/DELETE) where IDOR bisa affect other user's data.

6. **False positive in Autorize** — Autorize sometimes flag legitimate behavior as bypass. Always verify manually before reporting.

## Mitigasi Developer

- Implement authorization check on EVERY request, not just at UI level
- Use indirect reference maps (internal ID ≠ external ID exposure)
- Validate that current user owns/is authorized for object being accessed
- Use session-based authorization, not token-based assumption
- Apply principle of least privilege: each function has minimum required access
- Implement proper function-level access control, not just authentication
- Use security middleware that enforce access control for all endpoints
- Audit access control implementation regularly
- Implement rate limiting untuk prevent enumeration attacks
- Log all access control failures for monitoring

## Mini Quiz

1. IDOR (Insecure Direct Object Reference) terjadi ketika:
   a) Server tidak memvalidasi apakah user punya authorization untuk akses object tertentu
   b) User mengetik URL yang salah
   c) API mengembalikan error yang informatif
   d) Cookie tidak di-set dengan Secure flag

2. BOLA (Broken Object Level Authorization) adalah istilah OWASP untuk:
   a) Buffer overflow di application
   b) IDOR di konteks API security
   c) Broken authentication
   d) Data exfiltration via API

3. Horizontal privilege escalation terjadi ketika:
   a) Regular user mengakses admin function
   b) User A mengakses data user B tanpa authorization — keduanya di level privilege yang sama
   c) User mengakses resource yang tidak ada
   d) Admin mengakses resource regular user

4. Autorize Burp extension bekerja dengan cara:
   a) Scanning untuk XSS vulnerability
   b) Replay setiap request dengan high privilege token untuk compare response
   c) Brute force password
   d) Decode JWT token

5. Untuk testing IDOR secara sistematis, researcher harus:
   a) Hanya test endpoints yang visible di UI
   b) Login sebagai 2 different accounts dan compare access dengan each other's resources
   c) Hanya test GET requests
   d) Gunakan automated scanner saja

**Kunci Jawaban:** 1-A, 2-B, 3-B, 4-B, 5-B

## Assignment

1. **IDOR Hunt:** Pilih target lab. Login sebagai 2 different users. Identifikasi minimal 5 IDOR opportunities (endpoints dengan ID parameter). Test each dengan both accounts. Document findings.

2. **Autorize Audit:** Setup Autorize dengan 2 roles (regular + admin). Browse entire application sebagai regular user. Document semua bypass yang detected. Verify each manually.

3. **API Access Control Map:** Buat access control matrix untuk target API lab. Rows = roles (user, admin), Columns = endpoints. Mark: accessible / blocked / partially blocked. Identify gaps.

4. **Impact Analysis:** Untuk setiap IDOR yang ditemukan di assignment #1, buat impact statement yang jelas: apa yang bisa dilakukan attacker jika menemukan bug ini?

## Template Report Bug Bounty

```markdown
# Bug Report: IDOR Allowing Horizontal Privilege Escalation on Order History Endpoint

## Summary
Endpoint GET /api/orders/{order_id} tidak memvalidasi ownership order.
Authenticated user bisa mengakses order history milik user lain dengan
mengganti order_id parameter.

## Platform / Program
HackerOne | [Program Name]

## Severity
Medium | CVSS 6.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

## Vulnerability Type
IDOR / BOLA / Broken Access Control

## Asset / Endpoint
GET https://api.target.com/api/orders/{order_id}

## Description
Aplikasi menggunakan user-supplied order ID di path untuk retrieve order
details. Server tidak memvalidasi apakah order dengan ID tersebut milik user
yang membuat request. Authenticated user A bisa access order dari user B
dengan mengganti order_id di URL.

Request hanya memverifikasi bahwa user adalah authenticated (valid token),
tidak memverifikasi authorization untuk specific order.

## Steps to Reproduce
1. Login sebagai User A (email: user_a@email.com)
   POST /api/login
   {"email":"user_a@email.com","password":"Password123"}
   → Receive token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

2. Access own order (as expected behavior)
   GET /api/orders/1001
   Authorization: Bearer [token_user_a]
   → Response: {"order_id":1001,"user":"user_a@email.com","items":[...],"total":"$50"}

3. Enumerate other user's order ID (use Intruder with ID 1001-2000)
   GET /api/orders/1002
   Authorization: Bearer [token_user_a]
   → Response: {"order_id":1002,"user":"user_b@email.com","items":[...],"total":"$120"}
   User A berhasil access User B's order data!

4. Continue enumeration
   GET /api/orders/1003
   → Response: {"order_id":1003,"user":"user_c@email.com",...}

## Impact
- Privacy breach: Any authenticated user bisa view any other user's order data
- Information disclosure: Order history, purchase patterns, personal items purchased
- No authentication needed beyond having valid account
- Could be automated untuk extract entire database of orders

## Evidence
[Burp Screenshot: Request User A accessing own order 1001 - 200 OK]
[Burp Screenshot: Request User A accessing User B order 1002 - 200 OK with User B data]
[Burp Screenshot: Intruder attack results showing multiple successful unauthorized access]

## Remediation / Recommendation
1. Implement authorization check: verify order.user_id == current_user.id before returning order data
2. Use indirect object references (map internal order_id to external identifier)
3. Add audit logging untuk access to sensitive resources
4. Implement rate limiting untuk prevent enumeration
5. Add test coverage untuk access control scenarios
```