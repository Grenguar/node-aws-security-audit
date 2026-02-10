# Report Template

Generate the audit report using this exact structure. Adapt sections based on actual
findings — omit sections with zero findings but always include the summary, score,
and best practices.

---

## Scoring methodology

Calculate the Security Score using this formula:

1. Start at **100 points**
2. Subtract per finding:
   - Each Critical: **-15 points**
   - Each High: **-10 points**
   - Each Medium: **-5 points**
   - Each Low: **-2 points**
3. If zero Critical AND zero High findings: **+5 bonus** (capped at 100)
4. Minimum score: **0**

Grade scale:

| Grade | Range  | Meaning                                      |
|-------|--------|----------------------------------------------|
| A+    | 95-100 | Excellent — minimal risk                     |
| A     | 85-94  | Good — minor issues only                     |
| B     | 70-84  | Needs Improvement — address High/Medium      |
| C     | 50-69  | Concerning — Critical or multiple High        |
| D     | 25-49  | Poor — significant security gaps             |
| F     | 0-24   | Failing — immediate remediation required     |

---

## Output format

````markdown
# Node.js Security Audit Report

**Project:** {{project_name}}
**Date:** {{date}}
**Audited by:** Claude Code — Node.js Security Audit Skill by [Soroka Tech](https://sorokatech.com)
**Scope:** Static code analysis + dependency audit

---

## Security Score

**{{score}} / 100 ({{grade}})** — {{grade_meaning}}

```
[{{filled_bar}}{{empty_bar}}] {{score}}/100
```

| Grade | Range  | Meaning                                      |
|-------|--------|----------------------------------------------|
| A+    | 95-100 | Excellent — minimal risk                     |
| A     | 85-94  | Good — minor issues only                     |
| B     | 70-84  | Needs Improvement — address High/Medium      |
| C     | 50-69  | Concerning — Critical or multiple High        |
| D     | 25-49  | Poor — significant security gaps             |
| F     | 0-24   | Failing — immediate remediation required     |

**Score breakdown:**
- Starting score: 100
- Critical findings ({{n}}): -{{n * 15}}
- High findings ({{n}}): -{{n * 10}}
- Medium findings ({{n}}): -{{n * 5}}
- Low findings ({{n}}): -{{n * 2}}
- Adjustment: {{+5 if no Critical/High, else none}}
- **Final: {{score}} / 100 ({{grade}})**

---

## Findings Dashboard

**Total findings: {{total}}** | **Score: {{score}}/100 ({{grade}})**

| Severity     | Count | Top Finding                                    |
|--------------|-------|------------------------------------------------|
| 🔴 Critical  | {{n}} | {{title}} in `{{filepath}}:{{line}}`           |
| 🟠 High      | {{n}} | {{title}} across {{n}} files                  |
| 🟡 Medium    | {{n}} | {{title}} in `{{filepath}}:{{line}}`           |
| 🔵 Low       | {{n}} | {{title}} in `{{filepath}}:{{line}}`           |

{{2-3 sentence summary of the most important findings and overall posture.}}

---

## Node.js Runtime Assessment

| Property           | Value                  | Status   |
|--------------------|------------------------|----------|
| **Runtime Version** | {{Node.js version}}   | {{🔴 EOL / 🟡 Maintenance / 🟢 Active LTS}} |
| **OpenSSL Version** | {{OpenSSL version}}   | {{🔴 EOL / 🟡 Check patches / 🟢 Current}} |
| **V8 Engine**       | {{V8 version}}        | {{status}} |
| **engines.node**    | {{constraint or NONE}} | {{⚠ if missing}} |

{{If EOL, list the specific unpatched CVEs that apply to this version.
Reference version-vulnerabilities.md for the full CVE list.
Example: "Node.js 16.x is EOL since Sep 2023. Unpatched CVEs include
CVE-2023-30586 (OpenSSL engine permission bypass), CVE-2023-30589
(HTTP request smuggling via CR), and all subsequent security releases."}}

**Recommendation:** {{Upgrade to Node.js 24.x LTS / Ensure latest patch / OK}}

---

## Vulnerable Built-in API Usage

{{List each built-in module found with version-specific risks. Include only
modules that were actually detected in the codebase scan (node-version-check.sh).}}

| Module | Files Using It | Risk Level | Key CVE / Vulnerability |
|--------|---------------|------------|--------------------------|
| {{module}} | {{count}} files | {{🔴/🟠/🟡}} | {{CVE or risk description}} |

{{For each Critical/High finding, include the specific files and line numbers.}}

### {{Module Name}} — {{Risk Title}}

- **Files:** `{{filepath:line}}`, `{{filepath:line}}`
- **Risk:** {{Specific vulnerability explanation with CVE reference}}
- **Remediation:** {{What to replace it with}}

{{Repeat for each detected vulnerable built-in module.}}

---

## Framework Security Assessment

{{Include only if Express, Koa, webpack, NestJS, Fastify, or Bun was detected.}}

### {{Framework Name}} Security

| Check | Status | Details |
|-------|--------|---------|
| {{check_name}} | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |

{{List each framework-specific finding with file locations.}}

---

## AWS Lambda Security Assessment

{{Include only if Lambda/Serverless was detected.}}

| Check | Status | Details |
|-------|--------|---------|
| Event input validation | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| IAM least privilege | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| Function URL auth | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| Secrets management | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| /tmp directory hygiene | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| Logging sanitization | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |

{{List each Lambda-specific finding with file locations.}}

---

## Container Security Assessment

{{Include only if Docker/ECS/Fargate was detected.}}

| Check | Status | Details |
|-------|--------|---------|
| Non-root user | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| Multi-stage build | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| No --inspect flag | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| No secrets in Dockerfile | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| .dockerignore present | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| npm ci --omit=dev | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| SIGTERM handler | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| NODE_ENV=production | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| Image scanning in CI | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| ALB/WAF configured | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |

{{List each container/deployment-specific finding with file locations.}}

---

## AppSync / Amplify Security Assessment

{{Include only if AppSync/Amplify was detected.}}

| Check | Status | Details |
|-------|--------|---------|
| Authorization configuration | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| @auth directives on types | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| Introspection disabled in prod | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| API key rotation/expiry | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| Resolver input validation | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| Cognito security settings | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |
| Query depth/complexity limits | {{🟢 Pass / 🟠 Warning / 🔴 Fail}} | {{brief detail}} |

{{List each AppSync/Amplify-specific finding with file locations.}}

---

## Infrastructure as Code (IaC) Security Assessment

{{Include only if Terraform, CloudFormation/SAM, or Serverless Framework was detected.}}

### {{IaC Tool Name}} Security

| Check | Status | Details |
|-------|--------|---------|
| IAM least privilege | {{Pass / Warning / Fail}} | {{brief detail}} |
| No hardcoded secrets | {{Pass / Warning / Fail}} | {{brief detail}} |
| Function URL authentication | {{Pass / Warning / Fail}} | {{brief detail}} |
| Container not privileged | {{Pass / Warning / Fail}} | {{brief detail}} |
| No public IP assignment | {{Pass / Warning / Fail}} | {{brief detail}} |
| No debug ports/mode | {{Pass / Warning / Fail}} | {{brief detail}} |
| State file encryption | {{Pass / Warning / Fail}} | {{brief detail -- Terraform only}} |
| Deployment bucket encryption | {{Pass / Warning / Fail}} | {{brief detail -- Serverless only}} |
| Per-function IAM roles | {{Pass / Warning / Fail}} | {{brief detail -- Serverless only}} |
| API endpoint authorization | {{Pass / Warning / Fail}} | {{brief detail}} |
| WAF integration | {{Pass / Warning / Fail}} | {{brief detail}} |
| Node.js runtime not EOL | {{Pass / Warning / Fail}} | {{brief detail}} |

{{List each IaC-specific finding with file locations. Cross-reference
Checkov/tfsec IDs for Terraform, cfn-nag/AWS Config rules for CloudFormation.}}

---

## Findings

### 🔴 Critical

#### [VULN-001] {{Title}}

- **Severity:** Critical
- **OWASP Category:** {{A01–A10 with name}}
- **File:** `{{filepath}}:{{line}}`
- **Affected files:**
  - `{{filepath}}:{{line}}` — {{brief context of what this line does}}
  - `{{filepath}}:{{line}}` — {{brief context}}

**Vulnerable Code:**

```javascript
// {{filepath}}:{{line}}
{{exact code snippet from the project}}
```

**Explanation:**

{{Why this is dangerous. Reference the specific attack vector.}}

**Remediation:**

```javascript
{{fixed code example}}
```

---

{{Repeat for each finding, grouped under severity headers:
### 🔴 Critical, ### 🟠 High, ### 🟡 Medium, ### 🔵 Low}}

---

## Quick Wins (Biggest Score Impact)

These fixes are straightforward and will significantly improve your security score:

{{List the top 3-5 easiest fixes that give the biggest point improvement.
Prioritize fixes that: (1) affect multiple findings, (2) are a single npm install
+ one line of code, (3) are configuration changes.}}

1. **{{Fix title}}** (+{{points}} points) — {{one-line instruction}}
   Fixes: {{VULN-IDs}}

2. **{{Fix title}}** (+{{points}} points) — {{one-line instruction}}
   Fixes: {{VULN-IDs}}

3. **{{Fix title}}** (+{{points}} points) — {{one-line instruction}}
   Fixes: {{VULN-IDs}}

**Projected score after Quick Wins: {{projected_score}} / 100 ({{projected_grade}})**

---

## Dependency Audit Results

| Package | Current | Severity | CVE | Fix Version |
|---------|---------|----------|-----|-------------|
| {{pkg}} | {{ver}} | {{sev}} | {{cve}} | {{fix}} |

{{If npm audit found zero issues, state: "No known vulnerabilities found in dependencies."}}

---

## Security Best Practices Checklist

Use this as a hardening guide after addressing the findings above.

### Runtime & Built-in Security

- [ ] Running an actively supported Node.js LTS version (22.x or 24.x)
- [ ] `engines.node` set in package.json to prevent running on old versions
- [ ] `.nvmrc` or `.node-version` file present for team consistency
- [ ] No `new Buffer()` — use `Buffer.alloc()` or `Buffer.from()` only
- [ ] No `eval()`, `new Function()`, or `vm.runInNewContext()` with user input
- [ ] No `exec()`/`execSync()` — use `execFile()` or `spawn()` with arrays
- [ ] No `url.parse()` — use `new URL()` (WHATWG URL API)
- [ ] No `querystring` module — use `URLSearchParams`
- [ ] No `--inspect` flag in production Docker images or scripts
- [ ] `stream.pipeline()` used instead of `.pipe()` for error handling
- [ ] `zlib` decompression has `maxOutputLength` set
- [ ] No `crypto.createCipher()` — use `crypto.createCipheriv()` with AES-256-GCM

### Input & Output

- [ ] Validate all input with a schema library (Zod, Joi, class-validator)
- [ ] Use parameterized queries for all database operations
- [ ] Sanitize HTML output with DOMPurify or equivalent
- [ ] Set request body size limits (`express.json({ limit: '100kb' })`)
- [ ] Implement input length validation on all string fields

### Authentication & Sessions

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

### Error Handling & Logging

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

**Score: {{score}}/100 ({{grade}}) — {{grade_meaning}}**

{{1 sentence on most critical issue.}}
{{1 sentence on top priority action.}}
{{1 sentence on projected score after Quick Wins, e.g.: "Implementing the {{n}} Quick Wins above would improve your score to approximately {{projected_score}}/100 ({{projected_grade}})."}}

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

*Need a professional security assessment? Contact [Soroka Tech](https://sorokatech.com) for expert Node.js security consulting.*
````

## Severity criteria reference

Apply these when classifying each finding:

| Severity | Examples |
|----------|----------|
| **Critical** | EOL Node.js runtime, RCE via `eval(req.body)`, SQL injection, hardcoded production secrets, authentication bypass, unprotected admin routes |
| **High** | Stored XSS, CSRF on state-changing endpoints, SSRF to internal services, prototype pollution on user input, weak crypto on passwords, vulnerable built-in API usage |
| **Medium** | Missing security headers, verbose error leaking internals, no rate limiting, reflected XSS, outdated dependency with known CVE |
| **Low** | Missing `"use strict"`, `console.log` with PII, synchronous file I/O in request handlers, informational recommendations |

## Deduplication rules

- If the same pattern appears in multiple files, report it once with a note listing all affected files.
- Group related findings (e.g., multiple missing headers -> one "Security Headers" finding).
- Prioritize findings with working exploit paths over theoretical risks.

## Score presentation rules

- Always show the score prominently at the top of the report, before individual findings.
- The text progress bar should use block characters: `█` for filled, `░` for empty, 20 characters total (each = 5 points).
- Example for score 72: `[██████████████░░░░░░] 72/100`
- Always include the Quick Wins section — it makes the report actionable.
- The Summary footer repeats the score for quick reference when scrolling to the end.
- When calculating projected score for Quick Wins, add back the points from the findings that would be fixed.
