# Race Conditions & Concurrent Attack Scenarios

## Fokus Materi

Menguasai teknik exploitation untuk race condition vulnerabilities dan concurrent attack scenarios. Race condition adalah kelas bug yang sering missed oleh researcher karena require understanding of timing dan specialized testing tools.

## Deskripsi Materi

Race condition terjadi ketika output dari program bergantung pada relative timing dari events yang tidak dikoordinasikan dengan benar. Dalam konteks web security, ini berarti request yang dikirim secara parallel bisa menghasilkan state yang tidak konsisten dengan yang diharapkan developer.

TOCTOU (Time-Of-Check Time-Of-Use) adalah pattern spesifik dari race condition: program check kondisi pada waktu T1, tapi menggunakan hasilnya pada waktu T2. Between T1 dan T2, state bisa berubah, leading ke vulnerability.

Race conditions di web applications sering muncul di:
- Point redemption: redeem points 10 kali bersamaan, server belum update balance
- Coupon application: apply coupon berkali-kali sebelum server validates single-use
- Rate limiting: bypass limit dengan parallel requests yang processed before counter update
- OTP verification: verify OTP simultaneously, server accepts both before processing first

Burp Turbo Intruder adalah tool standar untuk testing race conditions: memungkinkan researcher untuk mengirim multiple request simultaneously dan observe inconsistent state results.

Race conditions sering mendapat bounty tinggi karena bisa di-exploit untuk:
- Financial fraud (double spend, coupon abuse)
- Rate limit bypass
- Privilege escalation (multiple verification step bypass)
- Data inconsistency

## Topik Pembahasan

• Race condition fundamentals: definisi, kenapa terjadi di web apps
• TOCTOU (Time-Of-Check Time-Of-Use) pattern dalam web context
• Burp Turbo Intruder: setup, configuration, parallel attack execution
• Race condition target patterns: rate limit bypass, promo code abuse, OTP bypass, balance manipulation
• Double-spend bug: exploit di point/credit/transfer systems
• Limit bypass: bypass per-user limit dengan parallel request
• Reproducing race condition secara konsisten untuk laporan
• Timing analysis dan documentation untuk report

## Tujuan Pembelajaran

Setelah sesi ini, peserta diharapkan mampu:
1. Identifikasi potential race condition vulnerabilities
2. Use Burp Turbo Intruder untuk trigger race conditions
3. Exploit race condition untuk financial fraud scenarios
4. Bypass rate limiting via parallel request techniques
5. Document race condition findings dengan timing evidence
6. Understand TOCTOU patterns di berbagai application contexts

## Real Case Bug Bounty Report

- Platform: HackerOne
- Program/Target: E-commerce platform (disclosed)
- Jenis vulnerability: Race condition allowing coupon reuse
- Link report: https://hackerone.com/reports/XXXXX
- Ringkasan kasus: Researcher menemukan coupon system yang hanya divalidasi sequentially. Coupon "SINGLE50" seharusnya hanya bisa digunakan sekali per user. Researcher menggunakan Turbo Intruder untuk send 50 parallel requests dengan coupon code yang sama. Server processed all requests before updating usage count, resulting in coupon applied 50 times instead of once.
- Root cause: Coupon usage check dan update tidak atomic. Check dilakukan di T1, update dilakukan di T2. Between T1 and T2 (for each parallel request), check still sees "unused" and allows application.
- Impact: 50x discount on purchase → significant financial loss for company. Severity: High.
- Pelajaran untuk bug hunter: Any functionality dengan "single use" atau "limited" constraints harus tested untuk race condition.

---

- Platform: Bugcrowd
- Program/Target: Payment platform
- Jenis vulnerability: Race condition leading to double-spend
- Link report: Public writeup
- Ringkasan kasus: Researcher menemukan that when transferring money between accounts, server check balance once at start of transfer, then execute transfer. If two transfers executed simultaneously for amount close to balance, both could succeed even though combined exceeds available balance. Researcher tested: Account has $1000. Send two $1000 transfer requests simultaneously. Server processed both, resulting in $2000 transferred from $1000 balance.
- Root cause: Balance check dilakukan sekali di awal, tidak di-compare sebelum setiap sub-operation.
- Impact: Double-spend → unauthorized money transfer. Severity: Critical.
- Pelajaran untuk bug hunter: Payment/transfer functionality harus tested untuk concurrent requests.

## Analisis Teknis

### Race Condition Attack Patterns

**Pattern 1: Parallel Request Race (Turbo Intruder)**

```
Scenario: Single-use coupon application

Normal flow:
1. Check if coupon used → No → Apply coupon → Mark as used

Race condition flow:
1. Request A: Check coupon → Not used (T1)
2. Request B: Check coupon → Not used (T1) [parallel]
3. Request C: Check coupon → Not used (T1) [parallel]
...
50. Request A: Apply coupon → Success
51. Request B: Apply coupon → Success [before update]
...

All parallel requests see "not used" because update happens after all checks complete
```

**Pattern 2: TOCTOU in Verification Flow**

```
OTP Verification TOCTOU:

Normal flow:
1. User request OTP verification
2. Server generate 6-digit code, store in DB with timestamp
3. User submit code
4. Server verify code matches DB

TOCTOU vulnerability:
1. User request OTP → Code generated: 123456, stored
2. User submit 123456 → Server starts verify
3. [Between verify start and complete] User request new OTP
4. Server generate new code: 789012, stored (overwrites old)
5. Verify completes with 123456 → Still matches (in memory before update check)
   OR verify reads new code 789012 but already validated 123456

Multiple OTPs processed before final state determined
```

**Pattern 3: Rate Limit TOCTOU**

```
Rate limit: 5 requests per minute

Normal flow:
1. Check request count in window
2. If < 5, allow + increment counter
3. If >= 5, block

TOCTOU vulnerability:
1. Request 1-5: All check count < 5, all increment
2. Between request 5 check and increment (or at same time):
   Request 6 also checks → Count still shows 4 (not yet incremented)
   Request 6 allowed!

With parallel requests: multiple requests see count as below limit before any increments
```

**Pattern 4: Insufficient Lock on Balance Operation**

```
Account balance: $1000

Race condition in transfer:
Thread 1: Read balance = 1000
Thread 2: Read balance = 1000
Thread 1: Write balance = 1000 - 1000 = 0
Thread 2: Write balance = 1000 - 1000 = 0
Result: $2000 transferred from $1000 balance

Both threads read balance before either writes
```

### Turbo Intruder Setup & Usage

**Installation:**
```bash
# Turbo Intruder is Burp Suite extension
# Download from PortSwigger or use pre-installed in Burp Professional
```

**Configuration:**
```python
# Turbo Intruder Python script for race condition

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10, pipeline=True)

    # Define the request template
    req = '''POST /api/coupon/apply HTTP/1.1
Host: target.com
Cookie: session=your_session_token
Content-Type: application/json

{"code":"SINGLE50"}'''

    # Send 20 requests as fast as possible
    for i in range(20):
        engine.queue(req)

    # Wait for responses
    engine.wait()

def handleResponse(response, request):
    # Analyze response for success indicators
    if 'discount_applied' in response.body or 'success' in response.body.lower():
        # Found race condition exploit
        print(f"[+] Success: {response.body}")
```

**Turbo Intruder for Rate Limit Bypass:**

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=50, pipeline=False)

    # Craft request that should be rate limited
    req = '''GET /api/data HTTP/1.1
Host: target.com
Authorization: Bearer token'''

    # Send burst of requests
    for i in range(50):
        engine.queue(req, pauseDuration=0.001)  # Minimal delay

    engine.wait()
```

### Race Condition Exploitation Steps

**Step 1: Identify Target**

Look for:
- "Limited" or "single use" features (coupons, redemption, signup bonus)
- Balance/credit operations (transfer, payment, withdrawal)
- Verification flows (OTP, email confirmation, approval)
- Rate-limited endpoints (search API, data fetch, file download)

**Step 2: Understand State Machine**

```
Question: What state is being checked, and when is it updated?

Check: Is coupon already used?
Update: Mark coupon as used

Check: Is balance sufficient?
Update: Deduct from balance

Check: OTP matches?
Update: Mark OTP as verified
```

**Step 3: Craft Race Attack**

```
For each parallel request:
1. Request fires with same data
2. All requests see pre-update state
3. All requests pass check
4. All requests execute action
5. State updates happen (after all checks)

Result: Multiple actions executed instead of single action
```

**Step 4: Verify and Measure**

```
1. Count successful operations (e.g., coupon applied 50 times)
2. Compare to expected (should be 1)
3. Quantify financial/operational impact
4. Document timing and response differences
```

### Race Condition in Different Contexts

**Context 1: Coupon/Promo**

```
Target: Apply single-use coupon
Attack: Send 100 parallel requests
Expected: 1 success, 99 failures
Actual: 100 successes (if vulnerable)
Impact: 100x discount abuse
```

**Context 2: Point Redemption**

```
Target: Redeem loyalty points (once per day)
Attack: Send 10 parallel requests
Expected: 1 success
Actual: 10 successes (if vulnerable)
Impact: 10x point redemption
```

**Context 3: Money Transfer**

```
Target: Transfer money between accounts
Attack: Send 2 transfers simultaneously close to balance limit
Expected: 1 success (second fails due to insufficient balance)
Actual: Both succeed (race condition)
Impact: Double-spend
```

**Context 4: Email Verification Bypass**

```
Target: Email verification for registration
Attack: Register with same email, parallel requests
Expected: Only one verification email sent
Actual: Multiple verification links generated
Impact: Could bypass email uniqueness check
```

## Praktik Lab Legal

### Lab 1: Coupon Race Condition Exploitation

- **Nama lab:** Turbo Intruder Race Attack
- **Tujuan:** Find dan exploit race condition di coupon application
- **Environment:** Burp Suite + Turbo Intruder, target lab dengan coupon system
- **Langkah praktik:**

  1. Obtain valid coupon code (single-use)
  2. Capture coupon application request di Burp
  3. Configure Turbo Intruder untuk parallel request sending
  4. Send 20-50 parallel requests dengan same coupon code
  5. Analyze responses: count successes vs failures
  6. If >1 success, race condition confirmed
  7. Quantify impact: coupon applied N times instead of 1

- **Expected result:** Peserta gain understanding bagaimana parallel requests bisa bypass single-use restrictions
- **Catatan keamanan:** Lab ini menggunakan target authorized. Jangan test di real systems tanpa authorization.

### Lab 2: Rate Limit Bypass via Race

- **Nama lab:** Rate Limit Bypass
- **Tujuan:** Bypass rate limiting dengan parallel request technique
- **Environment:** Burp Suite + Turbo Intruder, target lab dengan rate limiting
- **Langkah praktik:**

  1. Identify rate-limited endpoint
  2. Determine limit (e.g., 5 requests per minute)
  3. Send burst requests slightly above limit
  4. Test concurrent (parallel) vs sequential request behavior
  5. Analyze which approach bypasses limit
  6. Document successful bypass technique

- **Expected result:** Peserta menemukan method untuk bypass rate limiting
- **Catatan keamanan:** Lab ini untuk educational purpose di authorized environment.

### Lab 3: Balance Race Condition

- **Nama lab:** Double-Spend Attack
- **Tujuan:** Demonstrate race condition di balance transfer operation
- **Environment:** Burp Suite + Turbo Intruder, target lab dengan balance system
- **Langkah praktik:**

  1. Identify transfer/redemption endpoint
  2. Check current balance
  3. Send 2 parallel transfer requests (each close to balance)
  4. Analyze both requests succeed when they shouldn't
  5. Document double-spend vulnerability dan impact

- **Expected result:** Peserta mendemonstrasikan double-spend attack pattern
- **Catatan keamanan:** Lab ini menggunakan simulated financial system untuk educational purpose.

## Tools

- **Race condition testing:** Burp Turbo Intruder, custom scripts
- **Request timing:** Turbo Intruder built-in timing analysis
- **Concurrency testing:** parallel-cURL, custom Python threading

## Checklist Bug Hunter

- [ ] Identify all "limited" or "single use" features (coupons, redemptions, signup bonuses)
- [ ] Identify all balance/credit operations (transfer, payment, point redemption)
- [ ] Identify all verification flows (OTP, email confirmation, approval)
- [ ] Test each with parallel requests via Turbo Intruder
- [ ] Compare expected vs actual behavior under concurrent load
- [ ] Quantify financial/operational impact dari race condition
- [ ] Document timing differences dalam report
- [ ] Attempt to reproduce consistently sebelum reporting

## Common Mistakes

1. **Only test sequential requests** — Researcher yang only send request one-by-one tidak pernah discover race conditions. Parallel/concurrent testing required.

2. **Not understanding what state is checked and when** — Need to understand the state machine to identify race condition opportunities and design effective attack.

3. **Abaikan race condition di "minor" features** — Coupon abuse sounds small, but scaled could be significant financial impact.

4. **Not documenting timing** — Race condition report without timing evidence is hard to verify. Always include timing analysis and response comparison.

5. **Stopping at "found race condition" without demonstrating impact** — Just showing that parallel requests both work is step 1. Must quantify actual impact (financial loss, unauthorized access).

6. **Not using appropriate tools** — Turbo Intruder is designed untuk this. Manual testing won't achieve same level of concurrency.

## Mitigasi Developer

**Race Condition Prevention:**
- Use database transactions with proper isolation levels (SERIALIZABLE)
- Implement atomic operations: check and update in single operation, not separate
- Use pessimistic locking or optimistic locking with version checks
- Implement distributed locks for shared state operations
- Use database-level constraints (UNIQUE, CHECK)
- Never rely on application-level check without database enforcement

**Specific Mitigations:**
- Coupon: Use database UNIQUE constraint on (coupon_code, user_id) or use atomic increment
- Balance transfer: Use SELECT FOR UPDATE or atomic balance check-and-deduct in single transaction
- Rate limiting: Use atomic counter increment, not check-then-increment
- OTP: Use atomic verification, single check, immediate expiration after use

**Testing:**
- Implement concurrent testing in CI/CD pipeline
- Use chaos engineering tools untuk test race conditions in production-like environment

## Mini Quiz

1. Race condition terjadi ketika:
   a) Request lambat loading
   b) Output program bergantung pada timing dari events yang tidak dikoordinasikan dengan benar, menghasilkan inconsistent state
   c) Server timeout
   d) Semua jawaban benar

2. TOCTOU (Time-Of-Check Time-Of-Use) vulnerability terjadi ketika:
   a) Program check kondisi di satu waktu, tapi menggunakan hasilnya di waktu yang berbeda — state bisa berubah antara check dan use
   b) User menggunakan browser yang outdated
   c) Server tidak punya access control
   d) Semua jawaban salah

3. Burp Turbo Intruder digunakan untuk:
   a) Brute force password
   b) Mengirim parallel requests untuk trigger race conditions
   c) SQL injection scanning
   d) XSS detection

4. Race condition di coupon system memungkinkan:
   a) Coupon single-use bisa applied multiple times secara parallel
   b) Coupon expired lebih cepat
   c) Coupon tidak bisa digunakan
   d) Semua jawaban benar

5. Untuk prevent race condition, langkah yang paling penting adalah:
   a) Membuat website lebih cepat
   b) Menggunakan atomic operations dan proper database locking — check dan update dalam satu operasi
   c) Menambahkan CAPTCHA
   d) Menggunakan rate limiting saja

**Kunci Jawaban:** 1-B, 2-A, 3-B, 4-A, 5-B

## Assignment

1. **Race Condition Hunt:** Identifikasi semua "limited" features di target lab. Test masing-masing dengan Turbo Intruder parallel requests. Document findings.

2. **Rate Limit Bypass:** Find rate-limited endpoint. Develop bypass technique menggunakan parallel requests. Document results.

3. **Race Condition Impact Analysis:** Untuk finding yang berhasil, quantify impact: financial loss, unauthorized access, atau operational impact.

4. **TOCTOU Testing:** Identifikasi TOCTOU pattern di verification flow. Test apakah state bisa dimanipulated antara check dan use.

## Template Report Bug Bounty

```markdown
# Bug Report: Race Condition in Coupon Application Allowing Unlimited Use

## Summary
Single-use coupon bisa applied multiple kali secara simultaneous karena
coupon usage check dan update tidak atomic. Attacker bisa apply coupon
"SINGLE50" berkali-kali dalam parallel requests, circumventing single-use
restriction.

## Platform / Program
HackerOne | [Program Name]

## Severity
High | CVSS 7.4 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N)

## Vulnerability Type
Race Condition / TOCTOU / Insufficient Atomic Operation

## Asset / Endpoint
POST https://target.com/api/coupon/apply
Parameter: code (coupon code)

## Description
Coupon validation dan application dilakukan terpisah:
1. Check if coupon already used (SELECT count)
2. If not used, apply coupon (INSERT usage record)

Between check (step 1) and application (step 2), other parallel requests
also pass check, resulting in multiple applications.

Bug exists karena check-then-act bukan atomic operation.
Database tidak memiliki constraint untuk prevent duplicate usage.

## Steps to Reproduce
1. Obtain valid coupon "SINGLE50" (single-use per account)
2. Setup Turbo Intruder dengan request template:
   POST /api/coupon/apply
   {"code":"SINGLE50"}

3. Send 20 parallel requests simultaneously
4. Count successful applications:
   - Expected: 1 success, 19 failures
   - Actual: 20 successes, 0 failures

5. Verify all coupons applied by checking order history
   → All 20 orders show "SINGLE50" discount applied

6. Quantify impact:
   - Coupon value: $50 per use
   - Total abuse: 20 × $50 = $1,000 value extracted
   - Attacker could scale this further with more requests

## Impact
- Financial loss: Coupon intended for single use now applied multiple times
- Cost: $50 per successful abuse × number of parallel requests
- Could be automated to extract significant value
- Undermines coupon marketing investment
- If combined with account creation automation, could scale to unlimited abuse

## Evidence
[Burp Turbo Intruder Screenshot: 20 parallel requests queued]
[Burp Screenshot: Response comparison showing all 20 succeeded]
[Screenshot: Order history showing 20 successful coupon applications]
[Timing analysis showing requests processed within same millisecond window]

## Remediation / Recommendation
1. Make coupon check-and-apply atomic: single database transaction
2. Add database UNIQUE constraint: (coupon_code, user_id) to prevent duplicate usage
3. Use optimistic locking with version column
4. Implement proper transaction isolation level (SERIALIZABLE)
5. Add rate limiting per coupon per user in application layer
6. Log and alert for unusual coupon application patterns
7. Implement idempotency key untuk coupon redemption API
```