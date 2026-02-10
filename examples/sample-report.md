# Node.js Security Audit Report

**Project:** sample-vulnerable-app
**Date:** 2025-06-15
**Audited by:** Claude Code -- Node.js Security Audit Skill by [Soroka Tech](https://soroka.tech)
**Scope:** Static code analysis + dependency audit

---

## Security Score

**28 / 100 (D)** -- Poor

```text
[█████░░░░░░░░░░░░░░░] 28/100
```

| Grade | Range  | Meaning                                      |
|-------|--------|----------------------------------------------|
| A+    | 95-100 | Excellent -- minimal risk                    |
| A     | 85-94  | Good -- minor issues only                    |
| B     | 70-84  | Needs Improvement -- address High/Medium     |
| C     | 50-69  | Concerning -- Critical or multiple High      |
| **D** | **25-49** | **Poor -- significant security gaps**     |
| F     | 0-24   | Failing -- immediate remediation required    |

**Score breakdown:**

- Starting score: 100
- Critical findings (2): -30
- High findings (2): -20
- Medium findings (2): -10
- Low findings (1): -2
- Adjustment: none (Critical findings present)
- **Final: 28 / 100 (D) -- Score reflects serious security gaps that require immediate attention.**

---

## Findings Dashboard

**Total findings: 7** | **Score: 28/100 (D)**

| Severity    | Count | Top Finding                                            |
|-------------|-------|--------------------------------------------------------|
| Critical    | 2     | Hardcoded JWT secret in `src/server.js:26`             |
| High        | 2     | Missing helmet middleware across `src/server.js`       |
| Medium      | 2     | No rate limiting on authentication endpoints           |
| Low         | 1     | PII logged to console in `src/server.js:34`            |

The application exposes multiple Critical-severity attack vectors including a hardcoded JWT signing secret and direct use of `eval()` with user input. Combined with missing HTTP security headers and weak password hashing, the application is highly vulnerable to credential theft, remote code execution, and session hijacking. Immediate remediation is required before any production deployment.

---

## Node.js Runtime Assessment

| Property           | Value                  | Status   |
|--------------------|------------------------|----------|
| **Runtime Version** | Node.js 18.x (via Dockerfile / serverless.yml) | Maintenance LTS |
| **OpenSSL Version** | OpenSSL 3.0.x          | Check patches |
| **V8 Engine**       | 10.2.x                | Current  |
| **engines.node**    | NONE                   | Not specified in package.json |

Node.js 18.x is in maintenance LTS and will reach end-of-life in April 2025. While still receiving security patches, the project should plan migration to Node.js 22.x LTS. The absence of an `engines.node` constraint in `package.json` means the application could inadvertently run on an unsupported or vulnerable runtime version.

**Recommendation:** Upgrade to Node.js 22.x LTS. Add `"engines": { "node": ">=22" }` to `package.json`.

---

## Framework Security Assessment

### Express Security

| Check | Status | Details |
|-------|--------|---------|
| helmet middleware | Fail | Not installed or configured |
| CORS policy | Fail | `Access-Control-Allow-Origin: *` with wildcard methods |
| Body size limits | Fail | `express.json()` called without `limit` option |
| Session security | Fail | No session middleware detected |
| Trust proxy | Warning | Not configured -- IP-based rate limiting will not work behind a reverse proxy |
| Error handling | Fail | Stack traces exposed to clients in error handler |
| Static file dotfiles | Fail | `express.static()` without `dotfiles: 'deny'` -- exposes `.env`, `.git` |

### Webpack Security

| Check | Status | Details |
|-------|--------|---------|
| Source maps in production | Fail | `devtool: 'source-map'` exposes original source code |
| DefinePlugin env leaks | Fail | `process.env` stringified into bundle -- leaks all environment variables |
| Dev server in config | Warning | `devServer` block present in production webpack config |

---

## AWS Lambda Security Assessment

| Check | Status | Details |
|-------|--------|---------|
| Event input validation | Fail | `event.body` parsed and used directly in database query without validation |
| IAM least privilege | Fail | Wildcard `Action: '*'` and `Resource: '*'` in `serverless.yml` |
| Function URL auth | Fail | No authorizer on HTTP endpoints |
| Secrets management | Fail | `DB_PASSWORD` hardcoded in `serverless.yml` environment block |
| /tmp directory hygiene | Fail | `fs.writeFileSync('/tmp/...')` without cleanup -- disk exhaustion risk |
| Logging sanitization | Fail | Full event object logged via `console.log(event)` -- may contain tokens and PII |

---

## Container Security Assessment

| Check | Status | Details |
|-------|--------|---------|
| Non-root user | Fail | No `USER` directive in Dockerfile -- container runs as root |
| Multi-stage build | Fail | Single-stage build includes dev dependencies and build artifacts |
| No --inspect flag | Pass | No debug flags detected |
| No secrets in Dockerfile | Fail | `ARG DB_PASSWORD` cached in image layer history |
| .dockerignore present | Fail | No `.dockerignore` file -- `.env`, `.git`, `node_modules` copied into image |
| npm ci --omit=dev | Fail | Uses `npm install` instead of `npm ci --omit=dev` |
| SIGTERM handler | Fail | No graceful shutdown handler detected |
| NODE_ENV=production | Fail | Not set in Dockerfile |
| Image scanning in CI | Warning | No CI workflow with image scanning detected |
| ALB/WAF configured | Warning | No ALB or WAF configuration found |

---

## Infrastructure as Code (IaC) Security Assessment

### Serverless Framework Security

| Check | Status | Details |
|-------|--------|---------|
| IAM least privilege | Fail | `Action: '*'` / `Resource: '*'` grants unrestricted AWS access |
| No hardcoded secrets | Fail | `DB_PASSWORD: 'p@ssw0rd!'` in provider environment |
| Per-function IAM roles | Fail | Single provider-level role shared across all functions |
| API endpoint authorization | Fail | No `authorizer` on any HTTP event |
| cors: true | Fail | Permissive CORS on all endpoints |
| Deployment bucket encryption | Warning | No custom deployment bucket with encryption configured |
| Node.js runtime not EOL | Warning | `nodejs18.x` is maintenance LTS -- plan migration |
| serverless-offline in plugins | Warning | Dev-only plugin listed in production config |

---

## Findings

### Critical

#### [VULN-001] Hardcoded JWT Signing Secret

- **Severity:** Critical
- **OWASP Category:** A02:2021 -- Cryptographic Failures
- **File:** `src/server.js:26`

**Vulnerable Code:**

```javascript
// src/server.js:26
const JWT_SECRET = 'super-secret-key-123';
```

**Explanation:**

The JWT signing secret is hardcoded directly in the source code. Anyone with access to the repository can forge valid JWT tokens, impersonate any user, and bypass all authentication. This is especially dangerous if the repository is public or if the secret has been committed to version control history. An attacker can craft an arbitrary JWT payload, sign it with this known secret, and gain full access to protected endpoints.

**Remediation:**

```javascript
// Load the secret from an environment variable
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be set and at least 32 characters long');
}

// Sign with explicit algorithm and short expiry
const token = jwt.sign({ name }, JWT_SECRET, {
  algorithm: 'HS256',
  expiresIn: '15m',
});
```

---

#### [VULN-002] Remote Code Execution via eval() with User Input

- **Severity:** Critical
- **OWASP Category:** A03:2021 -- Injection
- **File:** `src/server.js:53`

**Vulnerable Code:**

```javascript
// src/server.js:53
const filter = eval('(' + req.query.filter + ')');
```

**Explanation:**

The `eval()` function executes arbitrary JavaScript code passed through the `filter` query parameter. An attacker can send a crafted request such as `GET /profile?filter=require('child_process').execSync('cat /etc/passwd')` to achieve full remote code execution on the server. This gives an attacker complete control over the application and the underlying system, including access to environment variables, file system, and network.

**Remediation:**

```javascript
// Replace eval() with safe JSON parsing and validation
app.get('/profile', (req, res) => {
  let filter;
  try {
    filter = JSON.parse(req.query.filter || '{}');
  } catch {
    return res.status(400).json({ error: 'Invalid filter format' });
  }

  // Validate filter against an allowed schema
  const allowedKeys = ['name', 'role', 'status'];
  const sanitized = Object.fromEntries(
    Object.entries(filter).filter(([key]) => allowedKeys.includes(key))
  );

  res.json({ filter: sanitized });
});
```

---

### High

#### [VULN-003] Missing HTTP Security Headers (No helmet)

- **Severity:** High
- **OWASP Category:** A05:2021 -- Security Misconfiguration
- **File:** `src/server.js`
- **Affected files:**
  - `src/server.js:8` -- Express app initialized without helmet middleware
  - `src/server.js:16-19` -- Manual CORS headers set instead of using a proper CORS library

**Vulnerable Code:**

```javascript
// src/server.js:8
const app = express();

// No helmet() middleware applied -- missing:
// - Content-Security-Policy
// - Strict-Transport-Security
// - X-Content-Type-Options
// - X-Frame-Options
// - X-XSS-Protection
```

**Explanation:**

Without the `helmet` middleware, the application serves responses without critical HTTP security headers. This leaves users vulnerable to clickjacking (no `X-Frame-Options`), MIME-type sniffing attacks (no `X-Content-Type-Options`), cross-site scripting (no `Content-Security-Policy`), and protocol downgrade attacks (no `Strict-Transport-Security`). These headers are a fundamental defense-in-depth measure for any web application.

**Remediation:**

```javascript
const helmet = require('helmet');

const app = express();
app.use(helmet());

// If you need to customize CSP:
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
}));
```

---

#### [VULN-004] Weak Password Hashing with MD5

- **Severity:** High
- **OWASP Category:** A02:2021 -- Cryptographic Failures
- **File:** `src/server.js:39`

**Vulnerable Code:**

```javascript
// src/server.js:39
const hash = crypto.createHash('md5').update(password).digest('hex');
```

**Explanation:**

MD5 is a cryptographically broken hash function. It is fast to compute, making brute-force and rainbow table attacks trivial. Modern GPUs can compute billions of MD5 hashes per second. Password hashing requires a slow, salted, purpose-built algorithm. Using MD5 means that if the database is compromised, all user passwords can be recovered in minutes.

**Remediation:**

```javascript
const bcrypt = require('bcrypt');

// When storing a password
const SALT_ROUNDS = 12;
const hash = await bcrypt.hash(password, SALT_ROUNDS);

// When verifying a password
const isValid = await bcrypt.compare(password, storedHash);
```

---

### Medium

#### [VULN-005] No Rate Limiting on Authentication Endpoints

- **Severity:** Medium
- **OWASP Category:** A07:2021 -- Identification and Authentication Failures
- **File:** `src/server.js:32`
- **Affected files:**
  - `src/server.js:32` -- `/login` route has no rate limiting
  - `src/server.js:51` -- `/profile` route has no rate limiting

**Vulnerable Code:**

```javascript
// src/server.js:32
app.post('/login', async (req, res) => {
  // No rate limiting -- attacker can attempt unlimited login attempts
  const { name, password } = req.body;
  // ...
});
```

**Explanation:**

Without rate limiting, an attacker can perform unlimited login attempts per second, enabling brute-force and credential-stuffing attacks. This is especially dangerous when combined with the weak MD5 password hashing (VULN-004), as there is no throttling to slow down automated attacks.

**Remediation:**

```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15-minute window
  max: 10,                    // limit to 10 attempts per window
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/login', loginLimiter, async (req, res) => {
  // ...
});
```

---

#### [VULN-006] Permissive CORS Configuration (Wildcard Origin)

- **Severity:** Medium
- **OWASP Category:** A01:2021 -- Broken Access Control
- **File:** `src/server.js:17`
- **Affected files:**
  - `src/server.js:17` -- `Access-Control-Allow-Origin: *` set on all responses
  - `src/server.js:18` -- `Access-Control-Allow-Methods: *` permits all HTTP methods
  - `src/handler.js:22` -- Lambda response also sets `Access-Control-Allow-Origin: *`
  - `serverless.yml:25` -- `cors: true` enables permissive CORS on all API Gateway endpoints

**Vulnerable Code:**

```javascript
// src/server.js:16-19
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', '*');
  next();
});
```

**Explanation:**

Setting `Access-Control-Allow-Origin: *` allows any website on the internet to make cross-origin requests to this API. If the API relies on cookies or session tokens for authentication, a malicious site can make authenticated requests on behalf of a logged-in user. Combined with `Access-Control-Allow-Methods: *`, an attacker's site can issue PUT, DELETE, and PATCH requests to modify or destroy data.

**Remediation:**

```javascript
const cors = require('cors');

app.use(cors({
  origin: ['https://your-frontend.example.com'],
  methods: ['GET', 'POST'],
  credentials: true,
}));
```

---

### Low

#### [VULN-007] PII Logged to Console

- **Severity:** Low
- **OWASP Category:** A09:2021 -- Security Logging and Monitoring Failures
- **File:** `src/server.js:34`
- **Affected files:**
  - `src/server.js:34` -- `console.log(req.body)` logs the full login request body including passwords
  - `src/handler.js:8` -- `console.log(event)` logs the full Lambda event including potential auth tokens

**Vulnerable Code:**

```javascript
// src/server.js:34
console.log(req.body);
// Logs: { name: "alice", password: "hunter2" }
```

**Explanation:**

Logging the full request body sends plaintext passwords and other personally identifiable information to stdout, where it can be captured by log aggregation services (CloudWatch, Datadog, Splunk). This violates data minimization principles and may constitute a compliance violation under GDPR, HIPAA, or PCI-DSS. In the Lambda handler, logging the full event object can expose authorization headers, API keys, and session tokens.

**Remediation:**

```javascript
const pino = require('pino');
const logger = pino({
  redact: ['req.body.password', 'req.headers.authorization'],
});

app.post('/login', async (req, res) => {
  logger.info({ user: req.body.name }, 'Login attempt');
  // ...
});
```

---

## Quick Wins (Biggest Score Impact)

These fixes are straightforward and will significantly improve your security score:

1. **Move JWT secret to environment variable** (+15 points) -- Replace the hardcoded string with `process.env.JWT_SECRET` and add validation.
   Fixes: VULN-001

2. **Replace eval() with JSON.parse()** (+15 points) -- Remove the `eval()` call and parse the filter parameter as JSON with schema validation.
   Fixes: VULN-002

3. **Install and configure helmet** (+10 points) -- Run `npm install helmet` and add `app.use(helmet())` before your routes.
   Fixes: VULN-003

**Projected score after Quick Wins: 68 / 100 (C)**

---

## Dependency Audit Results

| Package | Current | Severity | CVE | Fix Version |
|---------|---------|----------|-----|-------------|
| node-serialize | 0.0.4 | Critical | CVE-2017-5941 | No fix -- remove package |

`node-serialize` is a known-vulnerable package that enables remote code execution through crafted serialized objects. There is no safe version. Remove it entirely and use `JSON.parse()` / `JSON.stringify()` for serialization.

---

## Security Best Practices Checklist

### Runtime and Built-in Security

- [ ] Running an actively supported Node.js LTS version (22.x or 24.x)
- [ ] `engines.node` set in package.json to prevent running on old versions
- [ ] `.nvmrc` or `.node-version` file present for team consistency
- [ ] No `new Buffer()` -- use `Buffer.alloc()` or `Buffer.from()` only
- [x] No `eval()`, `new Function()`, or `vm.runInNewContext()` with user input (**FAILED -- see VULN-002**)
- [x] No `exec()`/`execSync()` -- use `execFile()` or `spawn()` with arrays (**FAILED -- `exec()` used in src/server.js:65**)
- [ ] No `--inspect` flag in production Docker images or scripts
- [ ] `stream.pipeline()` used instead of `.pipe()` for error handling

### Input and Output

- [ ] Validate all input with a schema library (Zod, Joi, class-validator)
- [ ] Use parameterized queries for all database operations
- [ ] Sanitize HTML output with DOMPurify or equivalent
- [ ] Set request body size limits (`express.json({ limit: '100kb' })`)
- [ ] Implement input length validation on all string fields

### Authentication and Sessions

- [ ] Hash passwords with bcrypt/scrypt/argon2 (cost >= 12)
- [ ] Sign JWTs with strong secret, short expiry (<= 15 min), explicit algorithm
- [ ] Set cookie flags: `httpOnly: true`, `secure: true`, `sameSite: 'strict'`
- [ ] Implement rate limiting on auth endpoints (express-rate-limit)
- [ ] Add brute-force protection (account lockout after N failures)

### HTTP Security

- [ ] Use `helmet` middleware for security headers
- [ ] Disable `x-powered-by` header
- [ ] Configure Content-Security-Policy
- [ ] Enable HSTS (`Strict-Transport-Security`)
- [ ] Set restrictive CORS policy (never `origin: '*'` in production)

### Data Protection

- [ ] Store secrets in environment variables (never in source code)
- [ ] Encrypt sensitive data at rest (AES-256-GCM)
- [ ] Enforce HTTPS everywhere
- [ ] Use crypto.timingSafeEqual for secret comparison
- [ ] Implement field-level encryption for PII

### Dependencies

- [ ] Run `npm audit` in CI/CD pipeline
- [ ] Pin dependency versions (use lockfiles)
- [ ] Remove unused dependencies
- [ ] Monitor for new CVEs with Snyk, Socket, or Dependabot
- [ ] Verify package integrity with `npm ci` (not `npm install`)

### Error Handling and Logging

- [ ] Never expose stack traces or internal errors to clients
- [ ] Use structured logging (pino, winston) with log redaction
- [ ] Log authentication events (login, logout, failed attempts)
- [ ] Monitor for anomalous patterns (spike in 4xx/5xx)
- [ ] Implement centralized error handling middleware

### Deployment

- [ ] Run Node.js as non-root user
- [ ] Set `NODE_ENV=production` in production
- [ ] Use process manager (pm2, systemd) for restarts
- [ ] Enable Node.js `--permission` flag where supported
- [ ] Use `"use strict"` or TypeScript strict mode

---

## Recommended Security Tools

| Tool | Purpose | Integration |
|------|---------|-------------|
| `helmet` | HTTP security headers | Express middleware |
| `express-rate-limit` | Rate limiting | Express middleware |
| `express-validator` / `zod` | Input validation | Route-level |
| `bcrypt` | Password hashing | Auth module |
| `csurf` or `csrf-csrf` | CSRF protection | Express middleware |
| `hpp` | HTTP parameter pollution protection | Express middleware |
| `pino` + `pino-http` | Structured logging | App-wide |
| `eslint-plugin-security` | Security linting | CI/CD |
| `snyk` / `socket` | Dependency monitoring | CI/CD |
| `npm audit` | Built-in vulnerability scanner | CI/CD |

---

## Summary

**Score: 28/100 (D) -- Poor**

The most critical issues are the hardcoded JWT secret (VULN-001) and remote code execution via `eval()` (VULN-002), both of which allow an attacker to fully compromise the application. The top priority is to remove the hardcoded secret, eliminate `eval()`, and install `helmet` for baseline HTTP security headers. Implementing the 3 Quick Wins above would improve your score to approximately 68/100 (C), and addressing the remaining High and Medium findings would bring the score above 80/100 (B).

---

## References

- [OWASP Top 10:2021](https://owasp.org/Top10/)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [Snyk Node.js Best Practices](https://snyk.io/articles/nodejs-security-best-practice/)
- [OWASP NodeGoat Project](https://github.com/OWASP/NodeGoat)

---

*This report was generated by static analysis and may contain false positives.
Manual review is recommended for all Critical and High findings.
This is not a substitute for a professional penetration test.*

*Need a professional security assessment? Contact [Soroka Tech](https://soroka.tech) for expert Node.js security consulting.*
