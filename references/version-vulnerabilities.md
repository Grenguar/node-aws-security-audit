# Node.js Version Vulnerabilities Reference

This file maps Node.js major versions to their known CVEs, vulnerable built-in
APIs, and bundled dependency risks. Use during Step 2 of the audit workflow.

---

## Release Status (as of Feb 2026)

| Version | Status            | EOL Date  | OpenSSL  | Blanket CVE      |
|---------|-------------------|-----------|----------|------------------|
| ≤ 8.x   | EOL               | Dec 2019  | 1.0.x    | CVE-2025-23087   |
| 10.x    | EOL               | Apr 2021  | 1.1.1    | CVE-2025-23087   |
| 12.x    | EOL               | Apr 2022  | 1.1.1    | CVE-2025-23087   |
| 14.x    | EOL               | Apr 2023  | 1.1.1    | CVE-2025-23087   |
| 16.x    | EOL               | Sep 2023  | 1.1.1    | CVE-2025-23087   |
| 17.x    | EOL (never LTS)   | Jun 2022  | 3.0.x    | CVE-2025-23087   |
| 18.x    | EOL               | Apr 2025  | 3.0.x    | —                |
| 19.x    | EOL (never LTS)   | Jun 2023  | 3.0.x    | CVE-2025-23088   |
| 20.x    | Maintenance LTS   | Apr 2026  | 3.0.x    | —                |
| 21.x    | EOL (never LTS)   | Jun 2024  | 3.0.x    | CVE-2025-23089   |
| 22.x    | Maintenance LTS   | Apr 2027  | 3.x     | —                |
| 23.x    | EOL (never LTS)   | Jun 2025  | 3.x     | —                |
| 24.x    | Active LTS        | Apr 2028  | 3.5.x   | —                |
| 25.x    | Current           | Jun 2026  | 3.5.x   | —                |

**Key:** All EOL versions with CVE-2025-23087/23088/23089 are automatically flagged
as vulnerable for every future CVE — the Node.js team applies all new CVEs to
EOL releases by default since they lack resources to evaluate each individually.

---

## Version-Specific CVE Details

### Node.js ≤ 8.x (EOL Dec 2019)

**Bundled dependencies:** OpenSSL 1.0.x, http_parser (legacy C parser), V8 6.x

**Key unpatched CVEs:**

- CVE-2019-15605 — HTTP request smuggling via malformed Transfer-Encoding
- CVE-2019-15604 — TLS assertion crash with malformed certificate string
- CVE-2019-15606 — HTTP header values not trimmed (trailing OWS)
- CVE-2018-12115 — Buffer.alloc() out-of-bounds write
- CVE-2018-7160 — DNS rebinding in inspector protocol

**Vulnerable built-in API patterns:**

- `http.createServer()` — uses legacy http_parser, all HRS CVEs apply
- `crypto.createCipher()` — no IV, weak key derivation (deprecated since v10)
- `Buffer(n)` constructor — uninitialized memory disclosure (fixed: Buffer.alloc)
- `require('url').parse()` — hostname spoofing via unicode characters

**Why it matters:** The old `http_parser` (C-based) was replaced with `llhttp`
in Node.js 12. All HTTP parsing CVEs from 2019+ were only fixed in llhttp.
Running a raw HTTP server on Node ≤8 means every request smuggling attack works.

---

### Node.js 10.x (EOL Apr 2021)

**Bundled dependencies:** OpenSSL 1.1.1, llhttp 2.x, V8 6.8

**Key unpatched CVEs:**

- CVE-2020-8265 — TLS use-after-free (memory corruption → potential RCE)
- CVE-2020-8287 — HTTP request smuggling (duplicate headers)
- CVE-2020-8174 — libuv buffer overflow in realpath (>256 byte paths)
- CVE-2020-8172 — TLS session reuse bypass on hostname mismatch
- CVE-2020-1971 — OpenSSL NULL pointer deref (DoS via GENERAL_NAME)

**Vulnerable built-in API patterns:**

- `tls.connect()` — use-after-free in TLSWrap (CVE-2020-8265)
- `dns.lookup()` — libuv uv__idna_toascii OOB read (CVE-2021-22918)
- `http` module with llhttp 2.x — smuggling via duplicate headers
- `crypto.createCipher()` — still available but deprecated and weak

---

### Node.js 12.x (EOL Apr 2022)

**Bundled dependencies:** OpenSSL 1.1.1, llhttp 2.x, V8 7.4–7.8

**Key unpatched CVEs:**

- CVE-2022-32212 — DNS rebinding in --inspect (bypass via invalid IPv4)
- CVE-2022-35255 — Weak randomness in WebCrypto keygen
- CVE-2022-32222 — OpenSSL config hijack on Linux/macOS (/home/iojs/...)
- CVE-2022-32213/32214/32215 — Transfer-Encoding HTTP smuggling (3 variants)
- CVE-2021-22921 — Windows privilege escalation (PATH + DLL hijacking)

**Vulnerable built-in API patterns:**

- `crypto.subtle.generateKey()` — weak entropy (CVE-2022-35255)
- `--inspect` flag — DNS rebinding to execute arbitrary code
- `http` module — 3 separate Transfer-Encoding parsing bugs
- OpenSSL config auto-loading from predictable paths

---

### Node.js 14.x (EOL Apr 2023)

**Bundled dependencies:** OpenSSL 1.1.1, llhttp 2.x/6.x, V8 8.1–8.4

**Key unpatched CVEs:**

- CVE-2023-23936 — CRLF injection in fetch() host header
- CVE-2023-24807 — ReDoS in Headers fetch API
- CVE-2023-23920 — Insecure ICU data loading via env variable
- CVE-2023-30589 — HTTP smuggling via CR without LF
- CVE-2022-32213/32214/32215 — Transfer-Encoding smuggling

**Vulnerable built-in API patterns:**

- `fetch()` (global) — CRLF injection in host header allows response splitting
- `http` module — CR-only delimiter accepted (RFC violation)
- `ICU_DATA` env variable — loads arbitrary data files
- All crypto on OpenSSL 1.1.1 — EOL since Sep 2023

---

### Node.js 16.x (EOL Sep 2023)

**Bundled dependencies:** OpenSSL 1.1.1/3.0, llhttp 6.x, V8 9.x

**Key unpatched CVEs:**

- CVE-2023-30586 — OpenSSL engine bypass of permission model
- CVE-2023-30585 — Windows installer privilege escalation
- CVE-2023-30589 — HTTP smuggling via empty CR-delimited headers
- CVE-2023-30590 — DiffieHellman key generation broken after setPrivateKey
- CVE-2023-30588 — Process crash via invalid x509 public key info

**Vulnerable built-in API patterns:**

- `crypto.setEngine()` — can disable permission model entirely
- `crypto.createDiffieHellman()` — generateKeys() silently fails
- `process.mainModule.__proto__.require()` — policy bypass
- `http2` — memory leak on peer disconnect without GOAWAY

**Note:** v16 still sees ~11M downloads/month despite being EOL for 2+ years.

---

### Node.js 18.x (EOL Apr 2025)

**Bundled dependencies:** OpenSSL 3.0, llhttp 6.x, V8 10.x

**Key unpatched CVEs:**

- CVE-2025-23083 — Worker thread privilege escalation via diagnostics_channel
- CVE-2025-23085 — HTTP/2 GOAWAY memory leak (DoS)
- CVE-2025-23084 — Windows drive name path traversal
- CVE-2024-22019 — HTTP request smuggling via content length obfuscation
- CVE-2024-21896 — Path traversal via symlinks bypasses permission model

**Vulnerable built-in API patterns:**

- `diagnostics_channel` — leaks internal worker instances
- `http2` server — memory leak without GOAWAY notification
- `path.join()` on Windows — doesn't treat drive names as special
- `fs.realpath()` with symlinks — bypasses permission restrictions

---

### Node.js 20.x (Maintenance LTS — EOL Apr 2026)

**Status:** Receiving security patches only. No new features.

**Recently patched CVEs (verify you have latest patch):**

- CVE-2025-59465 — HTTP/2 malformed HEADERS frame crash (High)
- CVE-2025-59466 — Uncatchable stack overflow via async_hooks (Medium)
- CVE-2025-59464 — TLS client certificate memory leak (Medium)
- CVE-2025-55132 — fs.futimes() bypasses read-only permission model (Low)

**Built-in API watch areas:**

- `async_hooks.createHook()` — makes stack overflow uncatchable (patched ≥20.18.2)
- `http2` server — malformed HEADERS frame crash (patched ≥20.18.2)
- OpenSSL 3.0 — does NOT support PBMAC1 (safe from some Jan 2026 CVEs)

---

### Node.js 22.x (Maintenance LTS — EOL Apr 2027)

**Status:** Receiving security patches.

**Recently patched CVEs:**

- CVE-2025-59465 — HTTP/2 HEADERS crash
- CVE-2025-59466 — async_hooks stack overflow DoS
- CVE-2026-21636 — Permission model bypass via Unix Domain Sockets
- CVE-2026-21637 — TLS PSK/ALPN callback exception DoS

**Built-in API watch areas:**

- `--permission` flag — UDS connections bypass --allow-net (patched ≥22.13.1)
- `fs.realpath()` — symlink path traversal bypasses permission model

---

### Node.js 24.x (Active LTS — EOL Apr 2028)

**Status:** Recommended for production. Actively maintained.

**Known issues (patched in latest):**

- CVE-2026-21636 — Permission model bypass via UDS
- CVE-2026-21637 — TLS callback exception causes DoS and FD leak
- V8 rapidhash — HashDoS reintroduced in v24.0.0, patched in v24.12.0+

**Built-in API watch areas:**

- Hash table operations — rapidhash makes HashDoS possible (patched ≥24.12.0)
- Ensure OpenSSL 3.5.x is at latest patch level

---

## Vulnerable Built-in Module Quick Reference

Use these grep patterns to detect usage of built-in modules with known version-
specific vulnerabilities. The `node-version-check.sh` script runs these automatically.

### Critical Risk (any version)

| Module          | Pattern                                               | Risk                        |
|-----------------|-------------------------------------------------------|-----------------------------|
| `child_process` | `exec(`, `execSync(`                                  | Command injection via shell |
| `vm`            | `vm.runInNewContext`, `vm.Script`, `vm.createContext`  | Sandbox escape              |
| `eval`          | `eval(`, `new Function(`                              | Arbitrary code execution    |
| `fs` + user input | `readFile(.*req.`, `createReadStream(.*req.`         | Path traversal              |

### High Risk (version-dependent)

| Module               | Affected Versions | Pattern                                   | CVE / Risk                          |
|----------------------|-------------------|--------------------------------------------|-------------------------------------|
| `http` / `https`     | ≤ 18.x            | `require('http')`, `http.createServer`     | HTTP request smuggling (8+ CVEs)    |
| `http2`              | ≤ 22.x            | `require('http2')`, `http2.createServer`   | CVE-2025-59465 (HEADERS crash)      |
| `crypto`             | all               | `createHash('md5')`, `createCipher(`       | Weak algorithms, no IV              |
| `crypto.subtle`      | 12.x              | `crypto.subtle.generateKey`               | CVE-2022-35255 (weak entropy)       |
| `tls`                | ≤ 10.x            | `tls.connect()`, `tls.createServer()`      | CVE-2020-8265 (use-after-free)      |
| `dns`                | ≤ 12.x            | `dns.lookup()`                             | CVE-2021-22918 (OOB read in libuv)  |
| `diagnostics_channel`| 20.x–23.x         | `require('diagnostics_channel')`           | CVE-2025-23083 (worker leak)        |
| `async_hooks`        | 20.x–24.x         | `async_hooks.createHook()`                 | CVE-2025-59466 (uncatchable crash)  |
| `fetch` (global)     | 14.x–18.x         | `fetch(`                                   | CVE-2023-23936 (CRLF injection)     |
| `net`                | 20.x–24.x         | `net.connect()` with socketPath            | CVE-2026-21636 (UDS permission bypass) |
| `path` (Windows)     | 18.x–22.x         | `path.join()`                              | CVE-2025-23084 (drive name traversal) |
| `inspector`          | ≤ 12.x            | `--inspect`                                | CVE-2022-32212 (DNS rebinding)      |

### Medium Risk

| Module             | Pattern                                              | Risk                          |
|--------------------|------------------------------------------------------|-------------------------------|
| `fs` (sync)        | `readFileSync`, `writeFileSync` in request handlers  | Event loop blocking → DoS     |
| `querystring`      | `require('querystring')`                             | Deprecated, use URLSearchParams |
| `url.parse()`      | `require('url').parse(`                              | Hostname spoofing (deprecated) |
| `os` / `process`   | `os.userInfo()`, `process.env` in responses          | Information disclosure        |
| `cluster`          | `require('cluster')`                                 | Shared server handle risks    |
| `string_decoder`   | On ≤ 8.x                                            | Buffer handling edge cases    |

---

## Why Older Versions Cause Vulnerabilities

### 1. Frozen OpenSSL

Node.js bundles its own OpenSSL copy. When a version goes EOL, that OpenSSL
never gets patched again. Example: Node.js 14 ships OpenSSL 1.1.1, which has
been EOL since Sep 2023 with dozens of unpatched CVEs since.

### 2. HTTP Parser Bugs Cascade

The llhttp parser had at least 8 distinct HTTP Request Smuggling CVEs between
2019–2023. Each fix only landed in supported versions. On Node ≤ 8, the old
C-based http_parser is used, which received zero of these fixes.

### 3. V8 Engine Carries JIT Bugs

Each Node.js major pins a V8 version. Chrome patches V8 continuously, but EOL
Node.js versions never receive those patches. V8 bugs include type confusion,
JIT compilation errors, and memory corruption — all exploitable in server contexts.

### 4. Blanket CVEs for EOL Versions

Since Jan 2025, the Node.js project applies ALL new CVEs to EOL versions by
default. The rationale: they lack resources to evaluate each EOL release
individually, so they assume all are vulnerable.

### 5. Ecosystem Drift

Popular packages drop support for old Node.js versions, forcing apps to stay
on outdated dependency versions that accumulate their own CVEs. npm audit
becomes increasingly noisy until critical vulnerabilities are unfixable.

---

## Remediation Priority

1. **Immediate:** If running Node.js ≤ 18.x → upgrade to 22.x or 24.x LTS
2. **Plan for:** If running Node.js 20.x → upgrade to 24.x before Apr 2026 EOL
3. **Verify:** If running Node.js 22.x/24.x → ensure latest patch version
4. **Lock:** Add `engines.node` to package.json to prevent accidental downgrades
5. **Automate:** Use `.nvmrc` / `.node-version` + CI checks to enforce version
