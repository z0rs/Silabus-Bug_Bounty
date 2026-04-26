# Business Logic & Impact Bugs

## Fokus Materi

Memahami dan mengeksploitasi business logic flaws — vulnerability yang unik untuk setiap aplikasi karena terkait dengan flow dan aturan bisnis, bukan technical vulnerability umum. Bug bounty tertinggi sering datang dari business logic bugs yang require creative thinking.

## Deskripsi Materi

Business logic flaws terjadi ketika aplikasi memiliki aturan bisnis yang diimplementasikan dengan benar secara technical, tapi aturannya sendiri bisa di-manipulasi atau di-abuse untuk keuntungan finansial atau unauthorized access. Berbeda dengan technical vulnerability (XSS, SQLi, IDOR), business logic bugs memerlukan pemahaman tentang apa aplikasi seharusnya lakukan.

Contoh business logic flaws yang nyata:
- Promo code yang hanya seharusnya bisa digunakan sekali tapi bisa digunakan berkali-kali
- Harga yang bisa di-manipulasi sebelum checkout
- Verification step yang bisa di-skip
- Workflow yang bisa dibypass untuk mendapat akses lebih awal

Business logic bugs sering mendapat bounty tinggi karena impact-nya langsung ke finansial atau operational perusahaan. Tapi juga challenging karena setiap aplikasi punya bisnis logic yang berbeda — tidak ada automated scanner yang bisa detect business logic flaws.

Pendekatan untuk finding business logic bugs memerlukan:
1. Memahami bisnis model aplikasi (pricing, promotions, subscriptions, workflow)
2. Mengidentifikasi dimana aturan bisnis diimplementasikan
3. Testing apakah aturan bisa di-manipulasi atau di-bypass
4. Dokumentasi impact dalam terms yang bisnis pahami (financial impact, operational impact)

## Topik Pembahasan

• Business logic flaw fundamentals: definisi, perbedaan dari technical vulnerability
• Contoh nyata: promo code reuse, negative quantity, skip step payment flow
• Payment flow abuse: refund manipulation, partial payment exploit, currency rounding
• Workflow bypass: skip email verifikasi, skip approval step di multi-step process
• Value mapping: hitung impact finansial dari business logic bug untuk justifikasi severity
• Case study: contoh bounty besar dari business logic (referensi HackerOne Hacktivity)
• Abuse scenario mapping: buat diagram alur dan tentukan titik penyimpangan
• Business logic di modern stack: GraphQL, API-first applications, microservices

## Tujuan Pembelajaran

Setelah sesi ini, peserta diharapkan mampu:
1. Identifikasi business logic flaws dari understanding aplikasi
2. Memahami pricing, promotion, dan workflow rules
3. Map abuse scenarios dan exploit opportunities
4. Dokumentasi impact dalam business/financial terms
5. Communicate business logic bugs secara efektif dalam report
6. Identify patterns yang repeatable untuk business logic testing

## Real Case Bug Bounty Report

- Platform: HackerOne
- Program/Target: E-commerce platform
- Jenis vulnerability: Price manipulation di checkout flow
- Link report: https://hackerone.com/reports/XXXXX (disclosed)
- Ringkasan kasus: Researcher menemukan bahwa harga item di checkout bisa di-manipulasi via API request interception. Dengan mengubah parameter `price` atau `amount` di request sebelum payment, researcher bisa purchase item dengan harga yang berbeda. Harga tidak divalidasi against server-side price, hanya accept what client sends.
- Root cause: Application trust client-side price without server-side validation. Price hanya stored as request parameter, not fetched from pricing database at checkout.
- Impact: Researcher purchased $500 item untuk $50. Financial loss untuk company. Severity: High (CVSS 7.1 karena requires authentication + some manipulation).
- Pelajaran untuk bug hunter: Always intercept and modify payment-related parameters. Client-side price never trusted should be golden rule.

---

- Platform: Bugcrowd
- Program/Target: Subscription service
- Jenis vulnerability: Subscription upgrade bypass — get premium features tanpa bayar
- Link report: Public writeup
- Ringkasan kasus: Application memiliki trial period untuk premium features. Researcher menemukan bahwa trial expiration hanya di-check client-side, not enforced server-side. After trial "expired" di UI, server still accept API requests dengan trial token untuk premium features. Researcher continue using premium features indefinitely without paying.
- Root cause: Server doesn't validate that trial period has ended; only client UI shows expiration. API accepts trial token after expiration.
- Impact: Free access to paid features. Financial impact depends on subscription price. Severity: High.
- Pelajaran untuk bug hunter: Don't trust client-side restrictions. Test API after UI shows "limit reached" — server might not enforce same limit.

## Analisis Teknis

### Business Logic Patterns

**Pattern 1: Price/Amount Manipulation**

```
Normal flow:
1. User browse products → prices fetched from database
2. User add to cart → price stored in session/database
3. Checkout → price sent in request → server process payment for that price

Vulnerable flow:
1. User browse products
2. User add to cart
3. Checkout: intercept request, modify "price" parameter
4. Server process payment for modified price (or server doesn't validate against DB price)

Attack vectors:
- Modify price parameter in request body
- Modify quantity to cause price miscalculation
- Intercept and change currency (USD vs IDR with different rates)
- Use negative quantity (refund instead of purchase)
```

**Pattern 2: Coupon/Promo Code Abuse**

```
Vulnerability patterns:
1. Race condition: apply same promo code simultaneously
2. Code reuse: single-use code used multiple times
3. Logic bypass: promo conditions not enforced server-side
4. Amount overflow: apply $100 coupon to $1 item = negative balance

Examples:
- Coupon "WELCOME10" should be single-use but server doesn't track usage
- Promo requires minimum purchase $50 but not validated server-side
- Coupon with max discount $10 but server accepts $100 discount
```

**Pattern 3: Workflow Step Bypass**

```
Multi-step process:
Step 1: User verification (email/phone)
Step 2: Identity check
Step 3: Admin approval
Step 4: Feature enabled

Bypass patterns:
- Directly access Step 4 URL without going through Step 1-3
- Replay old session token after verification expired
- Manipulate parameter to skip steps (step=4 instead of step=1)
- API accepts final state without validating intermediate steps
```

**Pattern 4: Integer Overflow / Type Confusion**

```
Price calculation:
- Item price: $0.99
- Quantity: -1
- Total: -$0.99 (negative = credit to user)

Quantity limit:
- Max quantity per order: 100
- But server stores as signed 8-bit integer (max 127)
- Order 127 items = OK, Order 128 items = overflow (negative)

Shipping fee logic:
- Free shipping if quantity > 10
- But quantity stored as signed int
- Order 32767 items → overflow to negative → free shipping
```

**Pattern 5: Time-Based Logic Abuse**

```
Trial period exploitation:
- Trial = 7 days from registration
- Server stores trial_end_date
- After trial_end_date, server should reject premium features

Vulnerability:
- If server checks timestamp from client (system time manipulation)
- Or if server doesn't validate at all, only UI shows warning

Rate limiting bypass:
- Limit: 5 API calls per minute
- Server validates based on request timestamp
- Client sends past/future timestamp to bypass

Subscription renewal:
- Subscription auto-renews on specific date
- User cancels before renewal date
- Server doesn't update status immediately, still charges if cancel happens between grace period
```

**Pattern 6: Insufficient Workflow Validation**

```
Approval workflow:
- User submits request
- Manager approves
- System executes

Attack:
- User submits request
- User directly call execution API (skip approval)
- System executes without manager approval

Order fulfillment:
- Order placed → Payment confirmed → Item shipped → Delivered
- Attack: Intercept "item shipped" message → Item marked as delivered without shipping
```

### Business Logic Testing Methodology

**Step 1: Understand the Business**

```markdown
Questions to answer:
1. What is the application's core business?
2. What are the monetization mechanisms? (subscription, transaction fee, ads)
3. What promotions/discounts exist? How are they validated?
4. What workflows exist? (registration, checkout, approval)
5. What are the constraints/limits? (rate limits, quantity limits, time limits)
6. What are the financial transactions?
```

**Step 2: Map the Attack Surface**

```python
# Create workflow map for an e-commerce application

Workflows:
1. User Registration → Email verification required
2. Product Purchase → Price + quantity + shipping
3. Coupon Application → Code + conditions + discount amount
4. Subscription → Start date + end date + features

Attack points:
- Registration: bypass email verification?
- Purchase: manipulate price/quantity?
- Coupon: reuse single-use code?
- Subscription: bypass trial limits?
```

**Step 3: Test Systematic Bypass**

```bash
# Workflow bypass testing
# If normal flow: step1 → step2 → step3 → step4

# Test direct access:
GET /step3 (skip step1 and step2)

# Test parameter manipulation:
POST /step3?step=3&previous_step_completed=true

# Test session manipulation:
Use session token from step1 for step4 request

# Test race condition:
Parallel requests to bypass sequential logic
```

**Step 4: Quantify Impact**

```markdown
# Financial impact calculation

Example 1: Price manipulation
- Product price: $500
- Manipulated price: $50
- Loss per transaction: $450
- Researcher purchased 10 items = $4,500 loss

Example 2: Subscription bypass
- Premium subscription: $99/month
- Researcher uses premium features for 1 year
- Financial impact: $1,188

Example 3: Coupon abuse
- Coupon value: 20% off, max $100
- Used 100 times by researcher
- Average order: $200
- Total discount abuse: $4,000
```

## Praktik Lab Legal

### Lab 1: Price Manipulation Testing

- **Nama lab:** Business Logic — Price Attack
- **Tujuan:** Find price manipulation vulnerability di checkout flow
- **Environment:** Burp Suite, target lab (e-commerce platform)
- **Langkah praktik:**

  1. Browse products, add to cart, proceed to checkout
  2. Intercept checkout request di Burp
  3. Modify price/amount parameters (decrease value)
  4. Submit modified request
  5. Observe if order goes through with manipulated price
  6. Test other variations: negative quantity, currency change, discount application
  7. Calculate financial impact

- **Expected result:** Peserta menemukan price manipulation vulnerability dan could purchase items at manipulated prices
- **Catatan keamanan:** Lab ini menggunakan environment dengan payment system yang realistic untuk testing. Jangan test di real e-commerce sites tanpa authorization.

### Lab 2: Workflow Bypass Challenge

- **Nama lab:** Business Logic — Workflow Bypass
- **Tujuan:** Bypass multi-step workflow untuk gain unauthorized access
- **Environment:** Burp Suite, target lab
- **Langkah praktik:**

  1. Map complete workflow for target functionality (e.g., account upgrade)
  2. Execute each step, noting URL, parameters, and session data
  3. Attempt to skip steps: go directly to later step URL
  4. Attempt parameter manipulation: force "step_completed=true" for earlier steps
  5. Test session reuse: use token from step 1 for step 4 request
  6. Document which bypass attempts work

- **Expected result:** Peserta mengidentifikasi workflow bypass vulnerabilities
- **Catatan keamanan:** Lab ini untuk authorized testing environment.

### Lab 3: Coupon/Promotion Abuse

- **Nama lab:** Business Logic — Promotion Exploitation
- **Tujuan:** Find dan exploit coupon/promotion logic flaws
- **Environment:** Burp Suite, target lab dengan coupon system
- **Langkah praktik:**

  1. Obtain valid coupon code
  2. Apply coupon — note terms: min purchase, max discount, usage limit
  3. Test each condition is enforced server-side:
     - Minimum purchase requirement
     - Maximum discount cap
     - Single-use vs multi-use enforcement
  4. Test race condition: apply same code multiple times simultaneously
  5. Test logic bypass: apply code that should be expired/invalid
  6. Calculate financial impact of abuse

- **Expected result:** Peserta menemukan coupon/promotion abuse vulnerabilities dan quantify financial impact
- **Catatan keamanan:** Lab ini untuk authorized testing.

## Tools

- **Interception:** Burp Suite (intercept dan modify requests)
- **Workflow testing:** Manual URL navigation, session manipulation
- **Calculation:** Spreadsheet untuk financial impact quantification
- **Documentation:** Notion/Obsidian untuk abuse scenario mapping

## Checklist Bug Hunter

- [ ] Understand core business model dari aplikasi target
- [ ] Map semua workflows: registration, checkout, upgrade, approval
- [ ] Identify monetization mechanisms: pricing, subscriptions, promotions
- [ ] Test price/amount manipulation di financial transactions
- [ ] Test coupon/promotion code abuse (race condition, logic bypass)
- [ ] Test workflow step bypass (skip verification steps)
- [ ] Test time-based logic abuse (trial expiry, rate limits)
- [ ] Test insufficient validation of user-controlled parameters
- [ ] Quantify impact dalam financial terms untuk severity justification
- [ ] Document abuse scenario clearly untuk report

## Common Mistakes

1. **Only test technical vulnerabilities, skip business logic** — Researcher yang hanya focus di XSS, SQLi, dll akan miss high-value business logic bugs yang tidak terdeteksi oleh scanner.

2. **Not understanding business context** — Researcher yang tidak understand pricing model, promotion rules, atau workflow akan tidak bisa identify abnormal behavior.

3. **Abaikan client-side restrictions** — UI shows "limit reached" but server might not enforce same limit. Always test API after UI restriction message appears.

4. **Not quantifying impact dalam financial terms** — Business logic bug dengan $0.01 manipulation sounds small, but scaled to thousands of transactions bisa sangat significant.

5. **Report without clear abuse scenario** — Report yang hanya describe technical flaw tanpa clear business impact tidak convey severity yang tepat.

## Mitigasi Developer

**Price/Financial Manipulation Prevention:**
- Always validate price server-side against pricing database at checkout
- Don't trust client-submitted price — fetch from trusted source
- Implement proper integer/string handling to prevent negative values
- Use proper decimal types (not float) for monetary calculations
- Validate all monetary calculations server-side

**Workflow/Business Rule Enforcement:**
- Enforce all business rules server-side, not just client-side
- Validate sequential workflow steps and don't trust client step indicators
- Use server-side state machine for workflow progression
- Implement proper authorization checks at each step

**Coupon/Promotion Validation:**
- Track coupon usage per user in database
- Enforce all conditions (minimum purchase, max discount) server-side
- Implement atomic coupon redemption to prevent race conditions
- Log coupon usage for anomaly detection

**Time-Based Logic:**
- Use server-side time, not client-provided timestamp
- Validate time-based limits server-side
- Implement proper subscription expiration checking
- Use database timestamps, not application server time

## Mini Quiz

1. Business logic flaw berbeda dari technical vulnerability karena:
   a) Business logic bugs lebih mudah ditemukan
   b) Business logic bugs terkait dengan abuse aplikasi berdasarkan aturan bisnis yang seharusnya, bukan technical implementation flaw
   c) Technical vulnerabilities lebih serious
   d) Business logic flaws hanya ada di financial applications

2. Price manipulation vulnerability terjadi ketika:
   a) Server mengrimkan harga yang salah ke client
   b) Client bisa modify price parameter dan server trust nilai tersebut tanpa validasi
   c) User mengklik tombol yang salah
   d) Semua jawaban benar

3. Untuk menemukan business logic flaws, researcher perlu:
   a) Hanya menggunakan automated scanner
   b) Memahami bisnis model aplikasi dan test apakah aturan bisnis bisa di-bypass atau dimanipulasi
   c) Hanya test SQL injection dan XSS
   d) Tidak perlu memahami bisnis aplikasi

4. Workflow bypass terjadi ketika:
   a) User mengklik tombol yang salah
   b) User bisa skip steps dalam multi-step process dengan langsung access later step URL atau manipulate parameters
   c) Server crash
   d) Semua jawaban benar

5. Impact dari business logic bug sebaiknya dikuantifikasi dalam:
   a) Technical severity score saja
   b) Financial impact: berapa kerugian yang bisa terjadi jika bug di-exploit
   c) Jumlah user yang affected
   d) Semua jawaban bisa relevant

**Kunci Jawaban:** 1-B, 2-B, 3-B, 4-B, 5-D

## Assignment

1. **Business Model Analysis:** Pilih target lab. Dokumentasikan: core business, monetization mechanism, pricing model, promotion rules, workflows. Identifikasi attack surface untuk business logic testing.

2. **Price Manipulation Test:** Lakukan price manipulation testing di checkout flow. Document price parameter yang bisa dimanipulasi dan financial impact.

3. **Workflow Bypass Audit:** Identifikasi semua multi-step workflows dan test untuk bypass opportunities. Document which steps could be skipped dan impact.

4. **Business Logic Bug Report:** Untuk setiap business logic finding, buat report dengan: abuse scenario, technical detail, financial impact quantification, dan recommendation.

## Template Report Bug Bounty

```markdown
# Bug Report: Price Manipulation in Checkout Allowing Items at 90% Discount

## Summary
Checkout endpoint menerima client-submitted price tanpa validasi terhadap
server-side pricing database. Attacker bisa purchase $500 item untuk $50
dengan memanipulasi price parameter di request.

## Platform / Program
HackerOne | [Program Name]

## Severity
High | CVSS 7.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N)

## Vulnerability Type
Business Logic / Price Manipulation / Insufficient Validation

## Asset / Endpoint
POST https://target.com/api/checkout

## Description
Aplikasi e-commerce mengambil harga dari client request tanpa validasi
server-side. Price di-request adalah client-controlled parameter, dan server
proses payment untuk jumlah tersebut tanpa compare against pricing database.

Attack scenario:
1. Normal: User checkout dengan item yang displays $500
2. Attack: User intercepts request, changes price to $50
3. Server: Process payment for $50, fulfill order for $500 item

## Steps to Reproduce
1. Browse target.com, select item priced at $500
2. Add to cart, proceed to checkout
3. Capture checkout request di Burp:
   POST /api/checkout
   {"items":[{"id":"item123","price":500,"quantity":1}],"total":500}

4. Modify price parameter:
   {"items":[{"id":"item123","price":50,"quantity":1}],"total":50}

5. Submit modified request
   → Order confirmed, payment processed for $50
   → Item shipped to user (value $500 purchased for $50)

6. Financial impact per transaction: $450 loss for company

## Impact
- Direct financial loss: each successful attack results in $450 loss
- If automated, could be used to purchase large quantities at manipulated prices
- Total potential impact: (price_difference × attack_scale) per attack
- Could be scaled to affect entire inventory
- Financial fraud with legal implications

## Evidence
[Burp Screenshot: Original checkout request with price=500]
[Burp Screenshot: Modified request with price=50]
[Burp Screenshot: Order confirmation showing item fulfilled]
[Burp Screenshot: Payment processed for $50 only]

## Remediation / Recommendation
1. Validate price server-side: fetch price from pricing database at checkout, don't trust client price
2. Implement price integrity check: calculated_price must match database price before payment processing
3. Use proper decimal types for monetary values (not floats)
4. Implement server-side price validation before order confirmation
5. Add logging of price discrepancies for fraud detection
6. Consider implementing price verification at multiple stages
```