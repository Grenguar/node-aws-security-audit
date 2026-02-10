#!/usr/bin/env bash
# node-version-check.sh — Check Node.js runtime version and scan for vulnerable built-in API usage.
# Outputs: node-version-audit.txt in the current directory.

set -uo pipefail

OUT="node-version-audit.txt"
SRC_PATTERN="--include=*.js --include=*.ts --include=*.mjs --include=*.cjs --include=*.jsx --include=*.tsx"
EXCLUDE="--exclude-dir=node_modules --exclude-dir=dist --exclude-dir=build --exclude-dir=.next --exclude-dir=coverage"

echo "=== Node.js Runtime & Built-in API Security Audit ===" > "$OUT"
echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$OUT"
echo "" >> "$OUT"

# ── 1. Runtime version detection ─────────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$OUT"
echo "## 1. Node.js Runtime Version" >> "$OUT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$OUT"

NODE_VERSION=""
MAJOR_VERSION=0

if command -v node &>/dev/null; then
  NODE_VERSION=$(node --version 2>/dev/null || echo "unknown")
  echo "Detected: $NODE_VERSION" >> "$OUT"
  MAJOR_VERSION=$(echo "$NODE_VERSION" | sed 's/v//' | cut -d. -f1)
else
  echo "⚠ Node.js not found in PATH" >> "$OUT"
fi

# Check .nvmrc, .node-version, package.json engines
echo "" >> "$OUT"
echo "### Version constraints in project files:" >> "$OUT"
if [ -f ".nvmrc" ]; then
  echo "  .nvmrc: $(cat .nvmrc)" >> "$OUT"
fi
if [ -f ".node-version" ]; then
  echo "  .node-version: $(cat .node-version)" >> "$OUT"
fi

# Extract engines.node from package.json
if [ -f "package.json" ]; then
  node -e "
    const pkg = require('./package.json');
    if (pkg.engines && pkg.engines.node) {
      console.log('  package.json engines.node: ' + pkg.engines.node);
    } else {
      console.log('  package.json: No engines.node constraint (risk: may run on any version)');
    }
  " 2>/dev/null >> "$OUT" || echo "  Could not parse package.json" >> "$OUT"
fi

# Check Dockerfile for Node version
DOCKERFILES=$(find . -maxdepth 3 -name "Dockerfile*" -not -path "*/node_modules/*" 2>/dev/null)
if [ -n "$DOCKERFILES" ]; then
  echo "" >> "$OUT"
  echo "### Docker base images:" >> "$OUT"
  for DF in $DOCKERFILES; do
    IMAGES=$(grep -E "^FROM\s+node" "$DF" 2>/dev/null || true)
    if [ -n "$IMAGES" ]; then
      echo "  $DF:" >> "$OUT"
      echo "$IMAGES" | while read -r line; do
        echo "    $line" >> "$OUT"
      done
    fi
  done
fi

# ── 2. EOL / CVE assessment ──────────────────────────────────────────────────
echo "" >> "$OUT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$OUT"
echo "## 2. Version Risk Assessment" >> "$OUT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$OUT"

if [ "$MAJOR_VERSION" -gt 0 ] 2>/dev/null; then
  if [ "$MAJOR_VERSION" -le 8 ]; then
    echo "🔴 CRITICAL: Node.js $NODE_VERSION is END-OF-LIFE (since 2019)" >> "$OUT"
    echo "   CVE-2025-23087 applies (blanket CVE for all v17 and earlier)" >> "$OUT"
    echo "   OpenSSL 1.0.x — dozens of unpatched CVEs" >> "$OUT"
    echo "   HTTP parser (http_parser) — all request smuggling CVEs unpatched" >> "$OUT"
    echo "   V8 engine — years of unpatched memory corruption bugs" >> "$OUT"
  elif [ "$MAJOR_VERSION" -le 10 ]; then
    echo "🔴 CRITICAL: Node.js $NODE_VERSION is END-OF-LIFE (since Apr 2021)" >> "$OUT"
    echo "   CVE-2025-23087 applies" >> "$OUT"
    echo "   Unpatched: CVE-2020-8265 (TLS use-after-free), CVE-2020-8287 (HTTP smuggling)" >> "$OUT"
    echo "   Unpatched: CVE-2020-8174 (libuv buffer overflow)" >> "$OUT"
    echo "   OpenSSL 1.1.1 — no longer receiving patches" >> "$OUT"
  elif [ "$MAJOR_VERSION" -le 12 ]; then
    echo "🔴 CRITICAL: Node.js $NODE_VERSION is END-OF-LIFE (since Apr 2022)" >> "$OUT"
    echo "   CVE-2025-23087 applies" >> "$OUT"
    echo "   Unpatched: CVE-2022-32212 (DNS rebinding in --inspect)" >> "$OUT"
    echo "   Unpatched: CVE-2022-35255 (weak WebCrypto keygen)" >> "$OUT"
    echo "   Unpatched: CVE-2022-32222 (OpenSSL config hijack)" >> "$OUT"
  elif [ "$MAJOR_VERSION" -le 14 ]; then
    echo "🔴 CRITICAL: Node.js $NODE_VERSION is END-OF-LIFE (since Apr 2023)" >> "$OUT"
    echo "   CVE-2025-23087 applies" >> "$OUT"
    echo "   Unpatched: CVE-2023-23936 (CRLF injection in fetch)" >> "$OUT"
    echo "   Unpatched: CVE-2023-30589 (HTTP request smuggling via CR)" >> "$OUT"
    echo "   Unpatched: CVE-2022-32213/32214/32215 (Transfer-Encoding smuggling)" >> "$OUT"
  elif [ "$MAJOR_VERSION" -le 16 ]; then
    echo "🔴 CRITICAL: Node.js $NODE_VERSION is END-OF-LIFE (since Sep 2023)" >> "$OUT"
    echo "   CVE-2025-23087 applies" >> "$OUT"
    echo "   Unpatched: CVE-2023-30586 (OpenSSL engine permission bypass)" >> "$OUT"
    echo "   Unpatched: CVE-2023-30585 (installer privilege escalation)" >> "$OUT"
    echo "   Unpatched: CVE-2023-30589/30590 (HTTP smuggling, DH key issues)" >> "$OUT"
    echo "   Still sees ~11M downloads/month despite EOL" >> "$OUT"
  elif [ "$MAJOR_VERSION" -le 17 ]; then
    echo "🔴 CRITICAL: Node.js $NODE_VERSION is END-OF-LIFE (odd release, never LTS)" >> "$OUT"
    echo "   CVE-2025-23087 applies (blanket CVE for all v17 and earlier)" >> "$OUT"
  elif [ "$MAJOR_VERSION" -le 18 ]; then
    echo "🔴 CRITICAL: Node.js $NODE_VERSION is END-OF-LIFE (since Apr 2025)" >> "$OUT"
    echo "   Unpatched: CVE-2025-23083 (worker thread privilege escalation)" >> "$OUT"
    echo "   Unpatched: CVE-2025-23085 (GOAWAY HTTP/2 memory leak)" >> "$OUT"
    echo "   Unpatched: CVE-2025-23084 (Windows path traversal)" >> "$OUT"
  elif [ "$MAJOR_VERSION" -eq 19 ]; then
    echo "🔴 CRITICAL: Node.js $NODE_VERSION is END-OF-LIFE (odd release, never LTS)" >> "$OUT"
    echo "   CVE-2025-23088 applies" >> "$OUT"
  elif [ "$MAJOR_VERSION" -eq 20 ]; then
    echo "🟡 MEDIUM: Node.js $NODE_VERSION is in Maintenance LTS (EOL Apr 2026)" >> "$OUT"
    echo "   Receiving security patches only — no new features" >> "$OUT"
    echo "   Recommend upgrading to v22.x or v24.x before EOL" >> "$OUT"
  elif [ "$MAJOR_VERSION" -eq 21 ]; then
    echo "🔴 CRITICAL: Node.js $NODE_VERSION is END-OF-LIFE (odd release, never LTS)" >> "$OUT"
    echo "   CVE-2025-23089 applies" >> "$OUT"
  elif [ "$MAJOR_VERSION" -eq 22 ]; then
    echo "🟢 OK: Node.js $NODE_VERSION is in Maintenance LTS (EOL Apr 2027)" >> "$OUT"
    echo "   Ensure you are on the latest patch version" >> "$OUT"
  elif [ "$MAJOR_VERSION" -eq 23 ]; then
    echo "🟡 MEDIUM: Node.js $NODE_VERSION is END-OF-LIFE (odd release, never LTS)" >> "$OUT"
    echo "   Upgrade to v24.x LTS" >> "$OUT"
  elif [ "$MAJOR_VERSION" -eq 24 ]; then
    echo "🟢 OK: Node.js $NODE_VERSION is Active LTS (EOL Apr 2028)" >> "$OUT"
    echo "   Recommended version for production" >> "$OUT"
  elif [ "$MAJOR_VERSION" -eq 25 ]; then
    echo "🟡 INFO: Node.js $NODE_VERSION is Current (not yet LTS)" >> "$OUT"
    echo "   Fine for development, use v24.x LTS for production" >> "$OUT"
  else
    echo "ℹ Node.js $NODE_VERSION — check https://github.com/nodejs/Release for status" >> "$OUT"
  fi
fi

# ── 3. OpenSSL version ────────────────────────────────────────────────────────
echo "" >> "$OUT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$OUT"
echo "## 3. Bundled OpenSSL Version" >> "$OUT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$OUT"

if command -v node &>/dev/null; then
  OPENSSL_VER=$(node -e "console.log(process.versions.openssl)" 2>/dev/null || echo "unknown")
  echo "OpenSSL: $OPENSSL_VER" >> "$OUT"

  # Flag old OpenSSL
  if echo "$OPENSSL_VER" | grep -qE "^1\.0\."; then
    echo "🔴 CRITICAL: OpenSSL 1.0.x is EOL — dozens of unpatched CVEs" >> "$OUT"
  elif echo "$OPENSSL_VER" | grep -qE "^1\.1\."; then
    echo "🔴 CRITICAL: OpenSSL 1.1.x is EOL (since Sep 2023)" >> "$OUT"
  elif echo "$OPENSSL_VER" | grep -qE "^3\.0\."; then
    echo "🟡 MEDIUM: OpenSSL 3.0.x — check for latest patch level" >> "$OUT"
  elif echo "$OPENSSL_VER" | grep -qE "^3\.[1-9]"; then
    echo "🟢 OK: OpenSSL $OPENSSL_VER" >> "$OUT"
  fi

  # Also show V8 version
  V8_VER=$(node -e "console.log(process.versions.v8)" 2>/dev/null || echo "unknown")
  echo "V8 engine: $V8_VER" >> "$OUT"
else
  echo "Cannot determine OpenSSL version — node not in PATH" >> "$OUT"
fi

# ── 4. Vulnerable built-in API usage scan ─────────────────────────────────────
echo "" >> "$OUT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$OUT"
echo "## 4. Vulnerable Built-in API Usage" >> "$OUT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$OUT"
echo "" >> "$OUT"

# --- 4a. HTTP module — request smuggling surface ---
echo "### 4a. http/https/http2 module (request smuggling surface)" >> "$OUT"
HTTP_USAGE=$(grep -rnl $SRC_PATTERN $EXCLUDE -E "require\(['\"]https?['\"]|from ['\"]https?['\"]|require\(['\"]http2['\"]|from ['\"]http2['\"]" . 2>/dev/null || true)
if [ -n "$HTTP_USAGE" ]; then
  echo "  ⚠ Direct http/https/http2 module usage found in:" >> "$OUT"
  echo "$HTTP_USAGE" | while read -r f; do echo "    - $f" >> "$OUT"; done
  echo "  Risk: Raw HTTP server/client is the attack surface for all HTTP request" >> "$OUT"
  echo "  smuggling CVEs. On EOL Node.js, the llhttp parser has unpatched HRS bugs." >> "$OUT"
  echo "  Recommendation: Use Express/Fastify with up-to-date Node.js. Never parse" >> "$OUT"
  echo "  raw HTTP headers manually." >> "$OUT"
else
  echo "  ✅ No direct http/https module usage found" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4b. crypto module — weak algorithms ---
echo "### 4b. crypto module (weak algorithms & deprecated APIs)" >> "$OUT"
CRYPTO_WEAK=$(grep -rn $SRC_PATTERN $EXCLUDE -E "createHash\(['\"]md5['\"]|createHash\(['\"]sha1['\"]|createCipher\(|createDecipher\(|createCipheriv\(['\"]des|createCipheriv\(['\"]rc4|createCipheriv\(['\"]blowfish|crypto\.pseudoRandomBytes|crypto\.rng\(|crypto\.prng\(" . 2>/dev/null || true)
if [ -n "$CRYPTO_WEAK" ]; then
  echo "  🔴 Weak/deprecated crypto API usage found:" >> "$OUT"
  echo "$CRYPTO_WEAK" | head -20 | while read -r line; do echo "    $line" >> "$OUT"; done
  echo "  Risk: MD5/SHA1 are collision-vulnerable. createCipher() uses weak key" >> "$OUT"
  echo "  derivation (no IV). DES/RC4/Blowfish are broken ciphers." >> "$OUT"
  echo "  Fix: Use SHA-256+, createCipheriv() with AES-256-GCM, crypto.randomBytes()." >> "$OUT"
else
  echo "  ✅ No weak crypto algorithms detected" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4c. child_process — command injection surface ---
echo "### 4c. child_process module (command injection surface)" >> "$OUT"
CP_USAGE=$(grep -rn $SRC_PATTERN $EXCLUDE -E "require\(['\"]child_process['\"]|from ['\"]child_process['\"]" . 2>/dev/null || true)
CP_EXEC=$(grep -rn $SRC_PATTERN $EXCLUDE -E "\bexec\(|\bexecSync\(" . 2>/dev/null | grep -v "execFile\|RegExp" || true)
if [ -n "$CP_USAGE" ] || [ -n "$CP_EXEC" ]; then
  echo "  ⚠ child_process usage found:" >> "$OUT"
  [ -n "$CP_USAGE" ] && echo "$CP_USAGE" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
  if [ -n "$CP_EXEC" ]; then
    echo "  🔴 exec()/execSync() found (shell injection risk):" >> "$OUT"
    echo "$CP_EXEC" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
    echo "  Risk: exec() runs through shell, enabling injection if user input is passed." >> "$OUT"
    echo "  Fix: Use execFile() or spawn() with argument arrays (no shell)." >> "$OUT"
  fi
else
  echo "  ✅ No child_process usage found" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4d. vm module — sandbox escape ---
echo "### 4d. vm module (sandbox escape)" >> "$OUT"
VM_USAGE=$(grep -rn $SRC_PATTERN $EXCLUDE -E "require\(['\"]vm['\"]|from ['\"]vm['\"]|vm\.runInNewContext|vm\.createContext|vm\.Script|vm\.runInThisContext" . 2>/dev/null || true)
if [ -n "$VM_USAGE" ]; then
  echo "  🔴 vm module usage found:" >> "$OUT"
  echo "$VM_USAGE" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
  echo "  Risk: Node.js vm module is NOT a security sandbox. It can be escaped" >> "$OUT"
  echo "  trivially: this.constructor.constructor('return process')().exit()" >> "$OUT"
  echo "  Fix: Use isolated-vm or worker_threads with transferable-only data." >> "$OUT"
else
  echo "  ✅ No vm module usage found" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4e. eval, Function constructor, unserialize ---
echo "### 4e. Dynamic code execution (eval/Function/unserialize)" >> "$OUT"
EVAL_USAGE=$(grep -rn $SRC_PATTERN $EXCLUDE -E "\beval\s*\(|new\s+Function\s*\(|unserialize\(|deserialize\(" . 2>/dev/null | grep -v "//.*eval\|\.test\.\|\.spec\.\|__test__\|__mock__" || true)
if [ -n "$EVAL_USAGE" ]; then
  echo "  🔴 Dynamic code execution found:" >> "$OUT"
  echo "$EVAL_USAGE" | head -15 | while read -r line; do echo "    $line" >> "$OUT"; done
  echo "  Risk: eval() and new Function() execute arbitrary code. unserialize()" >> "$OUT"
  echo "  from node-serialize enables RCE via crafted payloads." >> "$OUT"
  echo "  Fix: Use JSON.parse() for data, template literals for strings, safe parsers." >> "$OUT"
else
  echo "  ✅ No eval/Function/unserialize usage found" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4f. fs module — path traversal & sync I/O ---
echo "### 4f. fs module (path traversal & blocking I/O)" >> "$OUT"
FS_TRAVERSAL=$(grep -rn $SRC_PATTERN $EXCLUDE -E "(readFile|writeFile|readdir|unlink|rmdir|createReadStream|createWriteStream|access|stat)\s*\(.*req\.(params|query|body|url)" . 2>/dev/null || true)
FS_SYNC=$(grep -rn $SRC_PATTERN $EXCLUDE -E "readFileSync|writeFileSync|readdirSync|unlinkSync|rmdirSync|mkdirSync|statSync|existsSync|accessSync|appendFileSync" . 2>/dev/null | grep -v "config\|setup\|init\|bootstrap\|migration\|seed\|script\|cli\|build\|webpack\|vite\|jest\.config\|tsconfig" || true)
if [ -n "$FS_TRAVERSAL" ]; then
  echo "  🔴 User input in fs operations (path traversal risk):" >> "$OUT"
  echo "$FS_TRAVERSAL" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
  echo "  Risk: Attacker can use ../../etc/passwd to read arbitrary files." >> "$OUT"
  echo "  Fix: Use path.resolve() + validate against a base directory." >> "$OUT"
fi
if [ -n "$FS_SYNC" ]; then
  echo "  🟡 Synchronous fs operations in non-config files:" >> "$OUT"
  echo "$FS_SYNC" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
  echo "  Risk: Blocks the event loop, enabling DoS under load." >> "$OUT"
  echo "  Fix: Use async fs methods (fs.promises.*) in request handlers." >> "$OUT"
fi
if [ -z "$FS_TRAVERSAL" ] && [ -z "$FS_SYNC" ]; then
  echo "  ✅ No risky fs patterns found" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4g. net/tls/dgram — raw socket exposure ---
echo "### 4g. net/tls/dgram modules (raw socket exposure)" >> "$OUT"
NET_USAGE=$(grep -rn $SRC_PATTERN $EXCLUDE -E "require\(['\"]net['\"]|require\(['\"]tls['\"]|require\(['\"]dgram['\"]|from ['\"]net['\"]|from ['\"]tls['\"]|from ['\"]dgram['\"]" . 2>/dev/null || true)
if [ -n "$NET_USAGE" ]; then
  echo "  ⚠ Raw socket module usage found:" >> "$OUT"
  echo "$NET_USAGE" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
  echo "  Risk: On EOL Node.js, TLS has unpatched CVEs (use-after-free, cert" >> "$OUT"
  echo "  validation bypass). net module bypasses permission model on all versions." >> "$OUT"
  echo "  Fix: Keep Node.js updated. Validate all socket destinations." >> "$OUT"
else
  echo "  ✅ No raw socket module usage found" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4h. dns module — DNS rebinding ---
echo "### 4h. dns module (DNS rebinding)" >> "$OUT"
DNS_USAGE=$(grep -rn $SRC_PATTERN $EXCLUDE -E "require\(['\"]dns['\"]|from ['\"]dns['\"]|dns\.lookup|dns\.resolve" . 2>/dev/null || true)
if [ -n "$DNS_USAGE" ]; then
  echo "  ⚠ dns module usage found:" >> "$OUT"
  echo "$DNS_USAGE" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
  echo "  Risk: On Node.js ≤12, dns.lookup via libuv had out-of-bounds read" >> "$OUT"
  echo "  (CVE-2021-22918). DNS rebinding can bypass --inspect restrictions." >> "$OUT"
else
  echo "  ✅ No direct dns module usage found" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4i. process/os — information disclosure ---
echo "### 4i. process/os information disclosure" >> "$OUT"
INFO_LEAK=$(grep -rn $SRC_PATTERN $EXCLUDE -E "process\.env|process\.versions|process\.arch|process\.platform|os\.hostname|os\.userInfo|os\.networkInterfaces|os\.homedir" . 2>/dev/null | grep -iE "res\.(json|send|write|render)|response\.|\.emit\(" || true)
if [ -n "$INFO_LEAK" ]; then
  echo "  🟡 Potential information disclosure to clients:" >> "$OUT"
  echo "$INFO_LEAK" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
  echo "  Risk: Leaking process.env, versions, or OS info helps attackers fingerprint." >> "$OUT"
  echo "  Fix: Never send process/os data in HTTP responses." >> "$OUT"
else
  echo "  ✅ No information disclosure patterns found" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4j. async_hooks / diagnostics_channel — privilege escalation ---
echo "### 4j. async_hooks / diagnostics_channel (privilege escalation)" >> "$OUT"
ASYNC_HOOKS=$(grep -rn $SRC_PATTERN $EXCLUDE -E "require\(['\"]async_hooks['\"]|from ['\"]async_hooks['\"]|require\(['\"]diagnostics_channel['\"]|from ['\"]diagnostics_channel['\"]" . 2>/dev/null || true)
if [ -n "$ASYNC_HOOKS" ]; then
  echo "  ⚠ async_hooks/diagnostics_channel usage found:" >> "$OUT"
  echo "$ASYNC_HOOKS" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
  echo "  Risk: CVE-2025-23083 (Node.js 20-23) — diagnostics_channel can leak" >> "$OUT"
  echo "  internal worker instances for privilege escalation." >> "$OUT"
  echo "  CVE-2025-59466 — async_hooks makes stack overflow errors uncatchable," >> "$OUT"
  echo "  enabling DoS." >> "$OUT"
  echo "  Fix: Ensure Node.js ≥22.13.1 or ≥24.x. Minimize async_hooks in prod." >> "$OUT"
else
  echo "  ✅ No async_hooks/diagnostics_channel usage found" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4k. URL / fetch — SSRF and CRLF injection ---
echo "### 4k. URL / fetch (SSRF & CRLF injection)" >> "$OUT"
FETCH_USAGE=$(grep -rn $SRC_PATTERN $EXCLUDE -E "\bfetch\(.*req\.(body|query|params)|new URL\(.*req\.(body|query|params)|axios\.(get|post|put|delete|request)\(.*req\." . 2>/dev/null || true)
if [ -n "$FETCH_USAGE" ]; then
  echo "  🔴 User input passed to fetch/URL/axios:" >> "$OUT"
  echo "$FETCH_USAGE" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
  echo "  Risk: SSRF + CVE-2023-23936 (CRLF injection in fetch host header)" >> "$OUT"
  echo "  on Node.js ≤18. Attacker can access internal services." >> "$OUT"
  echo "  Fix: Validate URLs against allowlist. Block private IP ranges." >> "$OUT"
else
  echo "  ✅ No direct user-input-to-fetch patterns found" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4l. worker_threads — shared memory & message passing ---
echo "### 4l. worker_threads (shared memory risks)" >> "$OUT"
WORKER_USAGE=$(grep -rn $SRC_PATTERN $EXCLUDE -E "require\(['\"]worker_threads['\"]|from ['\"]worker_threads['\"]|new Worker\(" . 2>/dev/null || true)
SHARED_BUF=$(grep -rn $SRC_PATTERN $EXCLUDE -E "SharedArrayBuffer|Atomics\." . 2>/dev/null || true)
if [ -n "$WORKER_USAGE" ]; then
  echo "  ⚠ worker_threads usage found:" >> "$OUT"
  echo "$WORKER_USAGE" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
  if [ -n "$SHARED_BUF" ]; then
    echo "  🟡 SharedArrayBuffer/Atomics used (shared memory):" >> "$OUT"
    echo "$SHARED_BUF" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
    echo "  Risk: Race conditions on shared memory. On Node.js 20-23," >> "$OUT"
    echo "  CVE-2025-23083 allows diagnostics_channel to leak worker instances." >> "$OUT"
  fi
  echo "  Fix: Prefer message passing (postMessage) over SharedArrayBuffer." >> "$OUT"
  echo "  Ensure Node.js ≥22.13.1 to avoid worker leak CVE." >> "$OUT"
else
  echo "  ✅ No worker_threads usage found" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4m. inspector module — debug protocol exposure ---
echo "### 4m. inspector module (debug protocol exposure)" >> "$OUT"
INSPECTOR_USAGE=$(grep -rn $SRC_PATTERN $EXCLUDE -E "require\(['\"]inspector['\"]|require\(['\"]node:inspector['\"]|from ['\"]inspector['\"]|from ['\"]node:inspector['\"]|inspector\.open\(|--inspect" . 2>/dev/null || true)
if [ -n "$INSPECTOR_USAGE" ]; then
  echo "  🔴 Inspector/debug protocol usage found:" >> "$OUT"
  echo "$INSPECTOR_USAGE" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
  echo "  Risk: On Node.js ≤12, DNS rebinding can hijack the inspector (CVE-2022-32212)." >> "$OUT"
  echo "  Exposed inspector allows arbitrary code execution." >> "$OUT"
  echo "  Fix: Never expose --inspect in production. Bind to 127.0.0.1 only." >> "$OUT"
  echo "  Remove inspector module imports from production code." >> "$OUT"
else
  echo "  ✅ No inspector usage found" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4n. querystring module — deprecated, prototype pollution ---
echo "### 4n. querystring module (deprecated)" >> "$OUT"
QS_USAGE=$(grep -rn $SRC_PATTERN $EXCLUDE -E "require\(['\"]querystring['\"]|from ['\"]querystring['\"]|querystring\.parse\(|querystring\.decode\(" . 2>/dev/null || true)
if [ -n "$QS_USAGE" ]; then
  echo "  🟡 Deprecated querystring module usage found:" >> "$OUT"
  echo "$QS_USAGE" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
  echo "  Risk: querystring is deprecated since Node.js 14. Does not decode" >> "$OUT"
  echo "  percent-encoded characters correctly in all cases." >> "$OUT"
  echo "  Fix: Use URLSearchParams (global) or new URL().searchParams instead." >> "$OUT"
else
  echo "  ✅ No deprecated querystring module usage found" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4o. url.parse() — hostname spoofing ---
echo "### 4o. url.parse() (hostname spoofing, deprecated)" >> "$OUT"
URL_PARSE=$(grep -rn $SRC_PATTERN $EXCLUDE -E "url\.parse\(|require\(['\"]url['\"]\.parse|URL\.parse\(" . 2>/dev/null | grep -v "new URL(" || true)
if [ -n "$URL_PARSE" ]; then
  echo "  🟡 Legacy url.parse() usage found:" >> "$OUT"
  echo "$URL_PARSE" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
  echo "  Risk: url.parse() has known hostname spoofing bugs via unicode" >> "$OUT"
  echo "  characters. Deprecated since Node.js 11." >> "$OUT"
  echo "  Fix: Use new URL() (WHATWG URL API) for all URL parsing." >> "$OUT"
else
  echo "  ✅ No legacy url.parse() usage found" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4p. Buffer constructor — uninitialized memory ---
echo "### 4p. Buffer constructor (uninitialized memory disclosure)" >> "$OUT"
BUF_UNSAFE=$(grep -rn $SRC_PATTERN $EXCLUDE -E "new Buffer\(|Buffer\(\s*[0-9]|Buffer\.allocUnsafe\(|Buffer\.allocUnsafeSlow\(" . 2>/dev/null || true)
if [ -n "$BUF_UNSAFE" ]; then
  echo "  🔴 Unsafe Buffer usage found:" >> "$OUT"
  echo "$BUF_UNSAFE" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
  echo "  Risk: new Buffer(n) returns uninitialized memory that may contain" >> "$OUT"
  echo "  sensitive data from previous allocations (passwords, keys, etc)." >> "$OUT"
  echo "  Buffer.allocUnsafe() has the same risk if not immediately filled." >> "$OUT"
  echo "  Fix: Use Buffer.alloc(n) (zero-filled) or Buffer.from(data)." >> "$OUT"
else
  echo "  ✅ No unsafe Buffer patterns found" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4q. cluster module — shared server handle risks ---
echo "### 4q. cluster module (shared server handle)" >> "$OUT"
CLUSTER_USAGE=$(grep -rn $SRC_PATTERN $EXCLUDE -E "require\(['\"]cluster['\"]|from ['\"]cluster['\"]|cluster\.fork\(|cluster\.isMaster|cluster\.isPrimary" . 2>/dev/null || true)
if [ -n "$CLUSTER_USAGE" ]; then
  echo "  ⚠ cluster module usage found:" >> "$OUT"
  echo "$CLUSTER_USAGE" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
  echo "  Risk: Worker processes share server handles. A compromised worker can" >> "$OUT"
  echo "  intercept connections meant for others. On older Node.js, the cluster" >> "$OUT"
  echo "  scheduling algorithm was round-robin which could be abused for DoS." >> "$OUT"
  echo "  Fix: Prefer PM2 or container-based scaling. Validate IPC messages." >> "$OUT"
else
  echo "  ✅ No cluster module usage found" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4r. zlib — decompression bomb ---
echo "### 4r. zlib module (decompression bomb / DoS)" >> "$OUT"
ZLIB_USAGE=$(grep -rn $SRC_PATTERN $EXCLUDE -E "require\(['\"]zlib['\"]|from ['\"]zlib['\"]|zlib\.(inflate|gunzip|unzip|brotliDecompress)|createGunzip|createInflate|createUnzip|createBrotliDecompress" . 2>/dev/null || true)
if [ -n "$ZLIB_USAGE" ]; then
  echo "  ⚠ zlib decompression usage found:" >> "$OUT"
  echo "$ZLIB_USAGE" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
  echo "  Risk: Decompression bombs — a small compressed payload can expand to" >> "$OUT"
  echo "  gigabytes of memory, causing OOM and DoS." >> "$OUT"
  echo "  Fix: Set maxOutputLength option. Limit input size before decompression." >> "$OUT"
  echo "  Example: zlib.gunzip(buf, { maxOutputLength: 10 * 1024 * 1024 }, cb)" >> "$OUT"
else
  echo "  ✅ No zlib decompression usage found" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4s. stream without backpressure ---
echo "### 4s. stream piping (backpressure / DoS)" >> "$OUT"
STREAM_PIPE=$(grep -rn $SRC_PATTERN $EXCLUDE -E "\.pipe\(|pipeline\(|stream\.Readable|stream\.Writable|stream\.Transform" . 2>/dev/null | grep -v "node_modules" || true)
PIPE_NO_ERROR=$(grep -rn $SRC_PATTERN $EXCLUDE -E "\.pipe\(" . 2>/dev/null | grep -v "node_modules" | grep -v "\.on(.*error" || true)
if [ -n "$STREAM_PIPE" ]; then
  echo "  ⚠ Stream piping found:" >> "$OUT"
  echo "$STREAM_PIPE" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
  if [ -n "$PIPE_NO_ERROR" ]; then
    echo "  🟡 .pipe() without adjacent error handler:" >> "$OUT"
    echo "$PIPE_NO_ERROR" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
    echo "  Risk: .pipe() does not forward errors. Unhandled errors crash process." >> "$OUT"
    echo "  Missing backpressure handling can cause memory exhaustion." >> "$OUT"
    echo "  Fix: Use stream.pipeline() (handles errors + cleanup automatically)." >> "$OUT"
  fi
else
  echo "  ✅ No stream piping patterns found" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 4t. --experimental-permission model bypass checks ---
echo "### 4t. Permission model usage (bypass risks)" >> "$OUT"
PERM_MODEL=$(grep -rn $SRC_PATTERN $EXCLUDE -E "--permission|--allow-fs-read|--allow-fs-write|--allow-net|--allow-child-process|--allow-worker" . 2>/dev/null || true)
if [ -n "$PERM_MODEL" ]; then
  echo "  ⚠ Permission model flags found:" >> "$OUT"
  echo "$PERM_MODEL" | head -10 | while read -r line; do echo "    $line" >> "$OUT"; done
  echo "  Risk: Multiple permission model bypasses exist:" >> "$OUT"
  echo "    - CVE-2026-21636: UDS connections bypass --allow-net" >> "$OUT"
  echo "    - CVE-2025-55132: fs.futimes() bypasses read-only permissions" >> "$OUT"
  echo "    - CVE-2024-21896: Symlink path traversal bypasses fs permissions" >> "$OUT"
  echo "    - CVE-2023-30586: crypto.setEngine() disables permission model" >> "$OUT"
  echo "  Fix: Keep Node.js at latest patch. Do NOT rely solely on permission" >> "$OUT"
  echo "  model for security — use OS-level sandboxing (containers, seccomp)." >> "$OUT"
else
  echo "  ✅ No permission model usage found (not applicable)" >> "$OUT"
fi
echo "" >> "$OUT"

# ── 5. Framework-specific checks ───────────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$OUT"
echo "## 5. Framework-Specific Security Checks" >> "$OUT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$OUT"
echo "" >> "$OUT"

# Detect frameworks from package.json
USES_EXPRESS=false
USES_KOA=false
USES_WEBPACK=false
USES_NESTJS=false
USES_FASTIFY=false
USES_BUN=false
USES_LAMBDA=false
USES_DOCKER=false
USES_APPSYNC=false
USES_TERRAFORM=false
USES_CLOUDFORMATION=false
USES_SERVERLESS=false

if [ -f "package.json" ]; then
  node -e "
    const pkg = require('./package.json');
    const all = { ...pkg.dependencies, ...pkg.devDependencies };
    if (all['express']) console.log('express');
    if (all['koa']) console.log('koa');
    if (all['webpack']) console.log('webpack');
    if (all['@nestjs/core']) console.log('nestjs');
    if (all['fastify']) console.log('fastify');
    if (all['aws-lambda'] || all['@aws-sdk/client-lambda'] || all['serverless']) console.log('lambda');
    if (all['@aws-amplify/backend'] || all['aws-appsync'] || all['@aws-sdk/client-appsync']) console.log('appsync');
  " 2>/dev/null | while read -r fw; do
    echo "  Detected: $fw" >> "$OUT"
  done

  USES_EXPRESS=$(node -e "const p=require('./package.json'); const a={...p.dependencies,...p.devDependencies}; console.log(!!a['express'])" 2>/dev/null || echo "false")
  USES_KOA=$(node -e "const p=require('./package.json'); const a={...p.dependencies,...p.devDependencies}; console.log(!!a['koa'])" 2>/dev/null || echo "false")
  USES_WEBPACK=$(node -e "const p=require('./package.json'); const a={...p.dependencies,...p.devDependencies}; console.log(!!a['webpack'])" 2>/dev/null || echo "false")
  USES_NESTJS=$(node -e "const p=require('./package.json'); const a={...p.dependencies,...p.devDependencies}; console.log(!!a['@nestjs/core'])" 2>/dev/null || echo "false")
  USES_FASTIFY=$(node -e "const p=require('./package.json'); const a={...p.dependencies,...p.devDependencies}; console.log(!!a['fastify'])" 2>/dev/null || echo "false")
  USES_LAMBDA=$(node -e "const p=require('./package.json'); const a={...p.dependencies,...p.devDependencies}; console.log(!!(a['aws-lambda']||a['@aws-sdk/client-lambda']||a['serverless']))" 2>/dev/null || echo "false")
  USES_APPSYNC=$(node -e "const p=require('./package.json'); const a={...p.dependencies,...p.devDependencies}; console.log(!!(a['@aws-amplify/backend']||a['aws-appsync']||a['@aws-sdk/client-appsync']))" 2>/dev/null || echo "false")
fi

# Detect Bun runtime
if [ -f "bunfig.toml" ] || [ -f "bun.lockb" ] || [ -f "bun.lock" ]; then
  USES_BUN=true
  BUN_VERSION=$(bun --version 2>/dev/null || echo "unknown")
  echo "  Detected: bun (v$BUN_VERSION)" >> "$OUT"
fi

# Detect Docker/ECS/Fargate
if [ -f "Dockerfile" ] || [ -f "docker-compose.yml" ] || [ -f "docker-compose.yaml" ]; then
  USES_DOCKER=true
  echo "  Detected: docker" >> "$OUT"
fi

# Detect Lambda from config files
if [ -f "serverless.yml" ] || [ -f "serverless.yaml" ] || [ -f "serverless.ts" ] || [ -f "template.yaml" ] || [ -f "template.yml" ] || [ -f "sam.yaml" ]; then
  USES_LAMBDA=true
  echo "  Detected: lambda (from config files)" >> "$OUT"
fi

# Detect Amplify from directory structure
if [ -d "amplify" ] || [ -f "amplify/backend.ts" ]; then
  USES_APPSYNC=true
  echo "  Detected: amplify" >> "$OUT"
fi

# Detect Terraform
TF_FILES=$(find . -name "*.tf" -not -path "*/.terraform/*" -not -path "*/node_modules/*" 2>/dev/null | head -20)
if [ -n "$TF_FILES" ]; then
  USES_TERRAFORM=true
  TF_COUNT=$(echo "$TF_FILES" | wc -l | tr -d ' ')
  echo "  Detected: terraform ($TF_COUNT .tf files)" >> "$OUT"
fi

# Detect CloudFormation/SAM
if [ -f "template.yaml" ] || [ -f "template.yml" ] || [ -f "sam.yaml" ] || [ -f "sam.yml" ]; then
  USES_CLOUDFORMATION=true
  echo "  Detected: cloudformation/sam" >> "$OUT"
fi
CFN_FILES=$(find . -maxdepth 2 \( -name "*.template" -o -name "cdk.json" -o -name "cdk.context.json" \) -not -path "*/node_modules/*" 2>/dev/null | head -5)
if [ -n "$CFN_FILES" ]; then
  USES_CLOUDFORMATION=true
  echo "  Detected: cloudformation (template/CDK files)" >> "$OUT"
fi

# Detect Serverless Framework
if [ -f "serverless.yml" ] || [ -f "serverless.yaml" ] || [ -f "serverless.ts" ]; then
  USES_SERVERLESS=true
  SLS_VERSION=$(grep -E "frameworkVersion:" serverless.yml serverless.yaml 2>/dev/null | head -1 || echo "unknown")
  echo "  Detected: serverless framework ($SLS_VERSION)" >> "$OUT"
fi
echo "" >> "$OUT"

# --- 5a. Express checks ---
if [ "$USES_EXPRESS" = "true" ]; then
  echo "### 5a. Express.js Security" >> "$OUT"

  # Helmet
  HELMET=$(grep -rnl $SRC_PATTERN $EXCLUDE -E "require\(['\"]helmet['\"]|from ['\"]helmet['\"]" . 2>/dev/null || true)
  if [ -z "$HELMET" ]; then
    echo "  🟠 Missing helmet middleware — no security headers set" >> "$OUT"
  else
    echo "  ✅ helmet middleware found" >> "$OUT"
  fi

  # CORS
  CORS_WILD=$(grep -rn $SRC_PATTERN $EXCLUDE -E "cors\(\s*\)|cors\(\s*\{[^}]*origin\s*:\s*['\"]?\*" . 2>/dev/null || true)
  if [ -n "$CORS_WILD" ]; then
    echo "  🟠 Overly permissive CORS (origin: * or no config):" >> "$OUT"
    echo "$CORS_WILD" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Body parser limits
  BODY_NO_LIMIT=$(grep -rn $SRC_PATTERN $EXCLUDE -E "express\.json\(\s*\)|bodyParser\.json\(\s*\)" . 2>/dev/null || true)
  if [ -n "$BODY_NO_LIMIT" ]; then
    echo "  🟡 express.json() without size limit (DoS risk):" >> "$OUT"
    echo "$BODY_NO_LIMIT" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Trust proxy
  TRUST_PROXY=$(grep -rn $SRC_PATTERN $EXCLUDE -E "trust proxy.*true" . 2>/dev/null || true)
  if [ -n "$TRUST_PROXY" ]; then
    echo "  🟡 trust proxy set to true (should use specific IPs):" >> "$OUT"
    echo "$TRUST_PROXY" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Static dotfiles
  STATIC_NO_DOT=$(grep -rn $SRC_PATTERN $EXCLUDE -E "express\.static\(" . 2>/dev/null | grep -v "dotfiles" || true)
  if [ -n "$STATIC_NO_DOT" ]; then
    echo "  🟡 express.static() without dotfiles:'deny' (may expose .env):" >> "$OUT"
    echo "$STATIC_NO_DOT" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  echo "" >> "$OUT"
fi

# --- 5b. Koa checks ---
if [ "$USES_KOA" = "true" ]; then
  echo "### 5b. Koa Security" >> "$OUT"

  KOA_HELMET=$(grep -rnl $SRC_PATTERN $EXCLUDE -E "koa-helmet|@koa/helmet" . 2>/dev/null || true)
  if [ -z "$KOA_HELMET" ]; then
    echo "  🟠 Missing koa-helmet — no security headers set" >> "$OUT"
  else
    echo "  ✅ koa-helmet found" >> "$OUT"
  fi

  KOA_MASS=$(grep -rn $SRC_PATTERN $EXCLUDE -E "\.(create|update|findOneAndUpdate)\(\s*ctx\.request\.body" . 2>/dev/null || true)
  if [ -n "$KOA_MASS" ]; then
    echo "  🟠 Mass assignment — ctx.request.body passed directly to model:" >> "$OUT"
    echo "$KOA_MASS" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  KOA_STATIC=$(grep -rn $SRC_PATTERN $EXCLUDE -E "koa-static" . 2>/dev/null | grep -v "hidden" || true)
  if [ -n "$KOA_STATIC" ]; then
    echo "  🟡 koa-static without hidden:false (may serve dotfiles)" >> "$OUT"
  fi

  echo "" >> "$OUT"
fi

# --- 5c. Webpack checks ---
if [ "$USES_WEBPACK" = "true" ]; then
  echo "### 5c. Webpack Security" >> "$OUT"

  SRCMAP_PROD=$(grep -rn $SRC_PATTERN $EXCLUDE -E "devtool\s*:\s*['\"]source-map['\"]" . 2>/dev/null || true)
  EVAL_DEVTOOL=$(grep -rn $SRC_PATTERN $EXCLUDE -E "devtool\s*:\s*['\"].*eval" . 2>/dev/null || true)
  if [ -n "$SRCMAP_PROD" ] || [ -n "$EVAL_DEVTOOL" ]; then
    echo "  🟠 Source maps or eval devtool may be enabled in production:" >> "$OUT"
    [ -n "$SRCMAP_PROD" ] && echo "$SRCMAP_PROD" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
    [ -n "$EVAL_DEVTOOL" ] && echo "$EVAL_DEVTOOL" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  else
    echo "  ✅ No source maps or eval devtools detected" >> "$OUT"
  fi

  ENV_LEAK=$(grep -rn $SRC_PATTERN $EXCLUDE -E "DefinePlugin.*JSON\.stringify\(process\.env\)" . 2>/dev/null || true)
  if [ -n "$ENV_LEAK" ]; then
    echo "  🔴 DefinePlugin serializes ALL env vars into bundle (leaks secrets):" >> "$OUT"
    echo "$ENV_LEAK" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  DEV_SERVER=$(grep -rn $SRC_PATTERN $EXCLUDE -E "webpack-dev-server|devServer\s*:" . 2>/dev/null || true)
  if [ -n "$DEV_SERVER" ]; then
    echo "  🟡 webpack-dev-server config found (ensure not used in production):" >> "$OUT"
    echo "$DEV_SERVER" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  echo "" >> "$OUT"
fi

# --- 5d. NestJS checks ---
if [ "$USES_NESTJS" = "true" ]; then
  echo "### 5d. NestJS Security" >> "$OUT"

  # Helmet
  NEST_HELMET=$(grep -rnl $SRC_PATTERN $EXCLUDE -E "helmet" . 2>/dev/null || true)
  if [ -z "$NEST_HELMET" ]; then
    echo "  🟠 Missing helmet middleware — no security headers set" >> "$OUT"
  else
    echo "  ✅ helmet found" >> "$OUT"
  fi

  # ThrottlerGuard / rate limiting
  THROTTLER=$(grep -rnl $SRC_PATTERN $EXCLUDE -E "@nestjs/throttler|ThrottlerGuard|ThrottlerModule" . 2>/dev/null || true)
  if [ -z "$THROTTLER" ]; then
    echo "  🟠 Missing @nestjs/throttler — no rate limiting" >> "$OUT"
  else
    echo "  ✅ @nestjs/throttler found" >> "$OUT"
  fi

  # Global ValidationPipe
  VALIDATION_PIPE=$(grep -rn $SRC_PATTERN $EXCLUDE -E "useGlobalPipes.*ValidationPipe|APP_PIPE.*ValidationPipe" . 2>/dev/null || true)
  if [ -z "$VALIDATION_PIPE" ]; then
    echo "  🔴 No global ValidationPipe — all input may bypass validation" >> "$OUT"
  else
    echo "  ✅ Global ValidationPipe found" >> "$OUT"
  fi

  # class-validator
  CLASS_VALIDATOR=$(grep -rnl $SRC_PATTERN $EXCLUDE -E "class-validator|@IsString|@IsEmail|@IsNotEmpty" . 2>/dev/null || true)
  if [ -z "$CLASS_VALIDATOR" ]; then
    echo "  🟠 class-validator not found — DTOs may lack validation decorators" >> "$OUT"
  fi

  # Swagger in production
  SWAGGER=$(grep -rn $SRC_PATTERN $EXCLUDE -E "SwaggerModule\.setup\(" . 2>/dev/null || true)
  if [ -n "$SWAGGER" ]; then
    SWAGGER_COND=$(grep -rn $SRC_PATTERN $EXCLUDE -E "SwaggerModule" . 2>/dev/null | grep -c "NODE_ENV\|production\|isProd" || true)
    if [ "$SWAGGER_COND" = "0" ]; then
      echo "  🟠 Swagger may be exposed in production (no environment check):" >> "$OUT"
      echo "$SWAGGER" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
    fi
  fi

  # Controllers without guards
  UNGUARDED=$(grep -rnl $SRC_PATTERN $EXCLUDE -E "@Controller\(" . 2>/dev/null | while read -r f; do grep -qL "@UseGuards" "$f" 2>/dev/null && echo "$f"; done || true)
  if [ -n "$UNGUARDED" ]; then
    echo "  🟠 Controllers without @UseGuards:" >> "$OUT"
    echo "$UNGUARDED" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # SQL injection via raw queries (TypeORM/Prisma)
  RAW_SQL=$(grep -rn $SRC_PATTERN $EXCLUDE -E '\.query\(\s*`|\.where\(\s*`|\.\$queryRawUnsafe\(|\.\$executeRawUnsafe\(' . 2>/dev/null || true)
  if [ -n "$RAW_SQL" ]; then
    echo "  🔴 Potential SQL injection via raw queries:" >> "$OUT"
    echo "$RAW_SQL" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # GraphQL introspection
  GQL_INTRO=$(grep -rn $SRC_PATTERN $EXCLUDE -E "introspection\s*:\s*true" . 2>/dev/null || true)
  if [ -n "$GQL_INTRO" ]; then
    echo "  🟠 GraphQL introspection enabled (should be disabled in production):" >> "$OUT"
    echo "$GQL_INTRO" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Exception filter leaking stack
  FILTER_LEAK=$(grep -rn $SRC_PATTERN $EXCLUDE -E "exception\.stack|error\.stack|err\.stack" . 2>/dev/null | grep -iE "response|json|send" || true)
  if [ -n "$FILTER_LEAK" ]; then
    echo "  🟠 Exception filter may leak stack traces:" >> "$OUT"
    echo "$FILTER_LEAK" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  echo "" >> "$OUT"
fi

# --- 5e. Fastify checks ---
if [ "$USES_FASTIFY" = "true" ]; then
  echo "### 5e. Fastify Security" >> "$OUT"

  # @fastify/helmet
  FAST_HELMET=$(grep -rnl $SRC_PATTERN $EXCLUDE -E "@fastify/helmet|fastify-helmet" . 2>/dev/null || true)
  if [ -z "$FAST_HELMET" ]; then
    echo "  🟠 Missing @fastify/helmet — no security headers" >> "$OUT"
  else
    echo "  ✅ @fastify/helmet found" >> "$OUT"
  fi

  # @fastify/rate-limit
  FAST_RATE=$(grep -rnl $SRC_PATTERN $EXCLUDE -E "@fastify/rate-limit|fastify-rate-limit" . 2>/dev/null || true)
  if [ -z "$FAST_RATE" ]; then
    echo "  🟠 Missing @fastify/rate-limit — no rate limiting" >> "$OUT"
  else
    echo "  ✅ @fastify/rate-limit found" >> "$OUT"
  fi

  # Trust proxy misconfiguration
  FAST_TRUST=$(grep -rn $SRC_PATTERN $EXCLUDE -E "trustProxy\s*:\s*true" . 2>/dev/null || true)
  if [ -n "$FAST_TRUST" ]; then
    echo "  🟡 trustProxy set to true (should use specific IPs):" >> "$OUT"
    echo "$FAST_TRUST" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # reply.hijack()
  HIJACK=$(grep -rn $SRC_PATTERN $EXCLUDE -E "reply\.hijack\(\)" . 2>/dev/null || true)
  if [ -n "$HIJACK" ]; then
    echo "  🟡 reply.hijack() used (bypasses Fastify response lifecycle):" >> "$OUT"
    echo "$HIJACK" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Static file serving
  FAST_STATIC=$(grep -rn $SRC_PATTERN $EXCLUDE -E "@fastify/static|fastify-static" . 2>/dev/null || true)
  if [ -n "$FAST_STATIC" ]; then
    FAST_STATIC_SAFE=$(echo "$FAST_STATIC" | grep -c "allowedPath" || true)
    if [ "$FAST_STATIC_SAFE" = "0" ]; then
      echo "  🟡 @fastify/static without allowedPath (potential directory traversal)" >> "$OUT"
    fi
  fi

  echo "" >> "$OUT"
fi

# --- 5f. Bun runtime checks ---
if [ "$USES_BUN" = "true" ]; then
  echo "### 5f. Bun Runtime Security" >> "$OUT"

  # Bun.serve() without security headers
  BUN_SERVE=$(grep -rn $SRC_PATTERN $EXCLUDE -E "Bun\.serve\s*\(" . 2>/dev/null || true)
  if [ -n "$BUN_SERVE" ]; then
    BUN_HEADERS=$(grep -rn $SRC_PATTERN $EXCLUDE -E "Content-Security-Policy|X-Content-Type-Options|Strict-Transport-Security" . 2>/dev/null || true)
    if [ -z "$BUN_HEADERS" ]; then
      echo "  🟠 Bun.serve() without security headers (no helmet equivalent)" >> "$OUT"
    fi
    BUN_HOSTNAME=$(echo "$BUN_SERVE" | grep -c "hostname" || true)
    if [ "$BUN_HOSTNAME" = "0" ]; then
      echo "  🟡 Bun.serve() without hostname restriction (binds to 0.0.0.0 by default)" >> "$OUT"
    fi
  fi

  # Bun shell with raw escape hatch
  BUN_RAW=$(grep -rn $SRC_PATTERN $EXCLUDE -E "\{\s*raw\s*:" . 2>/dev/null || true)
  if [ -n "$BUN_RAW" ]; then
    echo "  🔴 Bun shell { raw: ... } escape hatch (bypasses escaping):" >> "$OUT"
    echo "$BUN_RAW" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # bun:sqlite injection
  BUN_SQL_INJECT=$(grep -rn $SRC_PATTERN $EXCLUDE -E 'db\.(query|prepare|run|exec)\s*\(\s*`' . 2>/dev/null | grep '\${' || true)
  if [ -n "$BUN_SQL_INJECT" ]; then
    echo "  🔴 bun:sqlite with template literal interpolation (SQL injection):" >> "$OUT"
    echo "$BUN_SQL_INJECT" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Non-cryptographic Bun.hash
  BUN_HASH=$(grep -rn $SRC_PATTERN $EXCLUDE -E "Bun\.hash\b" . 2>/dev/null || true)
  if [ -n "$BUN_HASH" ]; then
    echo "  🟠 Bun.hash() used (non-cryptographic — must not be used for security):" >> "$OUT"
    echo "$BUN_HASH" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Bun.file() path traversal
  BUN_FILE_TRAV=$(grep -rn $SRC_PATTERN $EXCLUDE -E 'Bun\.file\s*\(.*\$\{' . 2>/dev/null || true)
  if [ -n "$BUN_FILE_TRAV" ]; then
    echo "  🟠 Bun.file() with template literal (potential path traversal):" >> "$OUT"
    echo "$BUN_FILE_TRAV" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  echo "" >> "$OUT"
fi

# --- 5g. AWS Lambda checks ---
if [ "$USES_LAMBDA" = "true" ]; then
  echo "### 5g. AWS Lambda Security" >> "$OUT"

  # Event body used directly in queries
  EVENT_INJECT=$(grep -rn $SRC_PATTERN $EXCLUDE -E "event\.(body|queryStringParameters|pathParameters)" . 2>/dev/null | grep -iE "query\|exec\|find\|eval" || true)
  if [ -n "$EVENT_INJECT" ]; then
    echo "  🔴 Lambda event data used directly in queries (injection risk):" >> "$OUT"
    echo "$EVENT_INJECT" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Full event logging
  EVENT_LOG=$(grep -rn $SRC_PATTERN $EXCLUDE -E "console\.log\(.*event\)" . 2>/dev/null || true)
  if [ -n "$EVENT_LOG" ]; then
    echo "  🟠 Full Lambda event logged (may contain auth tokens):" >> "$OUT"
    echo "$EVENT_LOG" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Function URL without auth
  FUNC_URL_NONE=$(grep -rn $EXCLUDE -E "AuthType.*NONE|authorization_type.*NONE" . 2>/dev/null || true)
  if [ -n "$FUNC_URL_NONE" ]; then
    echo "  🔴 Lambda function URL with AuthType NONE (no authentication):" >> "$OUT"
    echo "$FUNC_URL_NONE" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # IAM over-permission
  IAM_STAR=$(grep -rn $EXCLUDE -E '"Action"\s*:\s*"\*"|"Resource"\s*:\s*"\*"' . 2>/dev/null || true)
  if [ -n "$IAM_STAR" ]; then
    echo "  🔴 IAM wildcard permissions (Action:* or Resource:*):" >> "$OUT"
    echo "$IAM_STAR" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # /tmp usage
  TMP_USAGE=$(grep -rn $SRC_PATTERN $EXCLUDE -E "/tmp/" . 2>/dev/null || true)
  if [ -n "$TMP_USAGE" ]; then
    echo "  🟡 /tmp directory usage (persists between warm invocations):" >> "$OUT"
    echo "$TMP_USAGE" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  echo "" >> "$OUT"
fi

# --- 5h. Docker/ECS/Fargate checks ---
if [ "$USES_DOCKER" = "true" ]; then
  echo "### 5h. Docker/ECS/Fargate Security" >> "$OUT"

  # Running as root
  for df in Dockerfile*; do
    [ -f "$df" ] || continue
    if ! grep -q "^USER" "$df" 2>/dev/null; then
      echo "  🔴 $df: No USER directive — container runs as root" >> "$OUT"
    fi
  done

  # --inspect flag
  INSPECT_FLAG=$(grep -rn -E "\-\-inspect|\-\-inspect-brk" Dockerfile* docker-compose*.yml package.json 2>/dev/null || true)
  if [ -n "$INSPECT_FLAG" ]; then
    echo "  🔴 --inspect flag found (debug port in production):" >> "$OUT"
    echo "$INSPECT_FLAG" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Secrets in Dockerfile
  DOCKER_SECRETS=$(grep -rnEi "^(ARG|ENV)\s+(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY|DB_PASS|AWS_ACCESS|AWS_SECRET|DATABASE_URL)" Dockerfile* 2>/dev/null || true)
  if [ -n "$DOCKER_SECRETS" ]; then
    echo "  🔴 Secrets in Dockerfile (ARG/ENV):" >> "$OUT"
    echo "$DOCKER_SECRETS" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # .dockerignore missing
  if [ ! -f ".dockerignore" ]; then
    echo "  🟠 Missing .dockerignore (node_modules, .env, .git may be in image)" >> "$OUT"
  fi

  # npm install instead of npm ci
  NPM_INSTALL=$(grep -rnE "RUN\s+npm\s+install" Dockerfile* 2>/dev/null || true)
  if [ -n "$NPM_INSTALL" ]; then
    echo "  🟡 npm install in Dockerfile (use npm ci --omit=dev for reproducible builds)" >> "$OUT"
  fi

  # Multi-stage build check
  for df in Dockerfile*; do
    [ -f "$df" ] || continue
    FROM_COUNT=$(grep -c "^FROM" "$df" 2>/dev/null || echo "0")
    if [ "$FROM_COUNT" -lt 2 ]; then
      echo "  🟡 $df: Single-stage build (use multi-stage to reduce image size)" >> "$OUT"
    fi
  done

  # SIGTERM handling
  SIGTERM=$(grep -rnl $SRC_PATTERN $EXCLUDE -E "process\.on\(\s*['\"]SIG(TERM|INT)" . 2>/dev/null || true)
  if [ -z "$SIGTERM" ]; then
    echo "  🟠 No SIGTERM handler found (needed for graceful ECS task shutdown)" >> "$OUT"
  fi

  # NODE_ENV not production
  NODE_ENV_SET=$(grep -rnE "^ENV\s+NODE_ENV\s+production|^ENV\s+NODE_ENV=production" Dockerfile* 2>/dev/null || true)
  if [ -z "$NODE_ENV_SET" ]; then
    echo "  🟡 NODE_ENV=production not set in Dockerfile" >> "$OUT"
  fi

  echo "" >> "$OUT"
fi

# --- 5i. AppSync/Amplify checks ---
if [ "$USES_APPSYNC" = "true" ]; then
  echo "### 5i. AppSync/Amplify Security" >> "$OUT"

  # API key in source
  API_KEY_SRC=$(grep -rn $SRC_PATTERN $EXCLUDE -E "da2-[a-z0-9]{26}|x-api-key" . 2>/dev/null | grep -v node_modules || true)
  if [ -n "$API_KEY_SRC" ]; then
    echo "  🔴 AppSync API key found in source code:" >> "$OUT"
    echo "$API_KEY_SRC" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # GraphQL introspection
  APPSYNC_INTRO=$(grep -rn $EXCLUDE -E "introspection" . 2>/dev/null | grep -iv "false\|disable" || true)
  if [ -n "$APPSYNC_INTRO" ]; then
    echo "  🟠 GraphQL introspection may be enabled" >> "$OUT"
  fi

  # @auth directive check
  GQL_FILES=$(find . -name "*.graphql" -not -path "*/node_modules/*" 2>/dev/null || true)
  if [ -n "$GQL_FILES" ]; then
    TYPES_NO_AUTH=$(grep -rn "^type\s" $GQL_FILES 2>/dev/null | grep -v "@auth\|@aws_" || true)
    if [ -n "$TYPES_NO_AUTH" ]; then
      echo "  🟠 GraphQL types without @auth directive:" >> "$OUT"
      echo "$TYPES_NO_AUTH" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
    fi
  fi

  # Cognito self-signup check
  SELF_SIGNUP=$(grep -rn $EXCLUDE -E "selfSignUpEnabled\s*:\s*true|allowUnauthenticatedIdentities" . 2>/dev/null || true)
  if [ -n "$SELF_SIGNUP" ]; then
    echo "  🟡 Cognito self-signup enabled or unauthenticated identities allowed" >> "$OUT"
  fi

  echo "" >> "$OUT"
fi

# --- 5j. Terraform IaC checks ---
if [ "$USES_TERRAFORM" = "true" ]; then
  echo "### 5j. Terraform IaC Security" >> "$OUT"

  # IAM wildcard actions
  IAM_WILDCARDS=$(rg -n 'actions\s*=\s*\[\s*"\*"\s*\]|"Action"\s*:\s*"\*"' --type tf 2>/dev/null || true)
  if [ -n "$IAM_WILDCARDS" ]; then
    echo "  🔴 IAM wildcard actions found:" >> "$OUT"
    echo "$IAM_WILDCARDS" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Hardcoded credentials
  HARDCODED_CREDS=$(rg -n 'AKIA[0-9A-Z]{16}|access_key\s*=\s*"[^${}"]+|secret_key\s*=\s*"[^${}"]+' --type tf 2>/dev/null || true)
  if [ -n "$HARDCODED_CREDS" ]; then
    echo "  🔴 Hardcoded AWS credentials in Terraform:" >> "$OUT"
    echo "$HARDCODED_CREDS" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Plaintext secrets in environment
  TF_SECRETS=$(rg -n '(PASSWORD|SECRET|API_KEY|PRIVATE_KEY|TOKEN|CREDENTIAL)\s*=\s*"[^${}"]+' --type tf 2>/dev/null || true)
  if [ -n "$TF_SECRETS" ]; then
    echo "  🔴 Plaintext secrets in Terraform environment variables:" >> "$OUT"
    echo "$TF_SECRETS" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Function URL without auth
  FUNC_URL_NONE=$(rg -n 'authorization_type\s*=\s*"NONE"' --type tf 2>/dev/null || true)
  if [ -n "$FUNC_URL_NONE" ]; then
    echo "  🔴 Lambda function URL without authentication:" >> "$OUT"
    echo "$FUNC_URL_NONE" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Privileged containers
  PRIVILEGED=$(rg -n '"privileged"\s*:\s*true|privileged\s*=\s*true' --type tf 2>/dev/null || true)
  if [ -n "$PRIVILEGED" ]; then
    echo "  🔴 Privileged container mode enabled:" >> "$OUT"
    echo "$PRIVILEGED" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # EOL Node.js runtime
  EOL_RUNTIME=$(rg -n 'runtime\s*=\s*"nodejs(10|12|14|16|18)\.x"' --type tf 2>/dev/null || true)
  if [ -n "$EOL_RUNTIME" ]; then
    echo "  🟠 EOL/deprecated Node.js runtime in Terraform:" >> "$OUT"
    echo "$EOL_RUNTIME" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Debug mode
  DEBUG_MODE=$(rg -n 'NODE_OPTIONS.*--inspect|NODE_ENV.*"(development|dev)"' --type tf 2>/dev/null || true)
  if [ -n "$DEBUG_MODE" ]; then
    echo "  🔴 Debug mode enabled in Terraform:" >> "$OUT"
    echo "$DEBUG_MODE" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Public IP assignment
  PUBLIC_IP=$(rg -n 'assign_public_ip\s*=\s*true' --type tf 2>/dev/null || true)
  if [ -n "$PUBLIC_IP" ]; then
    echo "  🟠 Public IP assigned to ECS tasks:" >> "$OUT"
    echo "$PUBLIC_IP" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Debug ports exposed
  DEBUG_PORTS=$(rg -n '"(containerPort|hostPort)"\s*:\s*(9229|5858)' --type tf 2>/dev/null || true)
  if [ -n "$DEBUG_PORTS" ]; then
    echo "  🔴 Node.js debug ports exposed in ECS:" >> "$OUT"
    echo "$DEBUG_PORTS" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # State file encryption
  for f in $(rg -l 'backend\s+"s3"' --type tf 2>/dev/null || true); do
    if ! grep -q 'encrypt' "$f" 2>/dev/null; then
      echo "  🟠 Missing S3 state file encryption: $f" >> "$OUT"
    fi
    if ! grep -q 'dynamodb_table' "$f" 2>/dev/null; then
      echo "  🟡 Missing state locking (DynamoDB): $f" >> "$OUT"
    fi
  done

  echo "" >> "$OUT"
fi

# --- 5k. CloudFormation/SAM IaC checks ---
if [ "$USES_CLOUDFORMATION" = "true" ]; then
  echo "### 5k. CloudFormation/SAM IaC Security" >> "$OUT"

  # Wildcard IAM
  CFN_WILDCARDS=$(grep -rnE 'Action:\s*["\x27]?\*["\x27]?|"Action"\s*:\s*"\*"' --include="*.yml" --include="*.yaml" --include="*.json" --include="*.template" . 2>/dev/null | grep -v node_modules || true)
  if [ -n "$CFN_WILDCARDS" ]; then
    echo "  🔴 Wildcard IAM actions in CloudFormation:" >> "$OUT"
    echo "$CFN_WILDCARDS" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Hardcoded secrets
  CFN_SECRETS=$(grep -rnEi "(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY|DB_PASS|AWS_ACCESS_KEY|AWS_SECRET):\s*['\"]?[A-Za-z0-9+/=_.@#\$%^&*-]{8,}" --include="*.yml" --include="*.yaml" . 2>/dev/null | grep -v "node_modules\|!Ref\|!Sub\|!GetAtt\|Fn::\|resolve:ssm\|resolve:secretsmanager" || true)
  if [ -n "$CFN_SECRETS" ]; then
    echo "  🔴 Hardcoded secrets in CloudFormation:" >> "$OUT"
    echo "$CFN_SECRETS" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # AWS access keys
  CFN_KEYS=$(grep -rnE "AKIA[A-Z0-9]{16}" --include="*.yml" --include="*.yaml" --include="*.json" --include="*.template" . 2>/dev/null | grep -v node_modules || true)
  if [ -n "$CFN_KEYS" ]; then
    echo "  🔴 AWS access keys in CloudFormation:" >> "$OUT"
    echo "$CFN_KEYS" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Privileged containers
  CFN_PRIV=$(grep -rnEi "Privileged:\s*(true|True|TRUE)" --include="*.yml" --include="*.yaml" . 2>/dev/null | grep -v node_modules || true)
  if [ -n "$CFN_PRIV" ]; then
    echo "  🔴 Privileged container in CloudFormation:" >> "$OUT"
    echo "$CFN_PRIV" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Lambda URL AuthType NONE
  CFN_URL_NONE=$(grep -rnE "AuthType:\s*NONE" --include="*.yml" --include="*.yaml" . 2>/dev/null | grep -v node_modules || true)
  if [ -n "$CFN_URL_NONE" ]; then
    echo "  🟠 Lambda URL AuthType NONE:" >> "$OUT"
    echo "$CFN_URL_NONE" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # ECS Exec enabled
  CFN_EXEC=$(grep -rnE "EnableExecuteCommand:\s*(true|True|TRUE)" --include="*.yml" --include="*.yaml" . 2>/dev/null | grep -v node_modules || true)
  if [ -n "$CFN_EXEC" ]; then
    echo "  🟠 ECS Exec enabled in CloudFormation:" >> "$OUT"
    echo "$CFN_EXEC" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  # Public IP on ECS
  CFN_PUBLIC=$(grep -rnE "AssignPublicIp:\s*ENABLED" --include="*.yml" --include="*.yaml" . 2>/dev/null | grep -v node_modules || true)
  if [ -n "$CFN_PUBLIC" ]; then
    echo "  🟠 Public IP assigned to ECS tasks:" >> "$OUT"
    echo "$CFN_PUBLIC" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
  fi

  echo "" >> "$OUT"
fi

# --- 5l. Serverless Framework checks ---
if [ "$USES_SERVERLESS" = "true" ]; then
  echo "### 5l. Serverless Framework Security" >> "$OUT"
  SLS_FILE="serverless.yml"
  [ ! -f "$SLS_FILE" ] && SLS_FILE="serverless.yaml"

  if [ -f "$SLS_FILE" ]; then
    # Wildcard IAM
    SLS_WILDCARDS=$(grep -rnE "Action\s*:\s*['\"]?\*['\"]?" "$SLS_FILE" 2>/dev/null || true)
    if [ -n "$SLS_WILDCARDS" ]; then
      echo "  🔴 Wildcard IAM actions in serverless.yml:" >> "$OUT"
      echo "$SLS_WILDCARDS" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
    fi

    SLS_RES_WILD=$(grep -rnE "Resource\s*:\s*['\"]?\*['\"]?" "$SLS_FILE" 2>/dev/null || true)
    if [ -n "$SLS_RES_WILD" ]; then
      echo "  🔴 Wildcard IAM resources in serverless.yml:" >> "$OUT"
      echo "$SLS_RES_WILD" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
    fi

    # Hardcoded secrets
    SLS_SECRETS=$(grep -rnEi "(PASSWORD|SECRET|KEY|TOKEN|PRIVATE|CREDENTIAL)\s*:\s*['\"][^\${][^'\"]{4,}['\"]" "$SLS_FILE" 2>/dev/null || true)
    if [ -n "$SLS_SECRETS" ]; then
      echo "  🔴 Hardcoded secrets in serverless.yml:" >> "$OUT"
      echo "$SLS_SECRETS" | head -5 | while read -r line; do echo "    $line" >> "$OUT"; done
    fi

    # Function URL without auth
    SLS_FUNC_URL=$(grep -rnE "url:\s*true" "$SLS_FILE" 2>/dev/null || true)
    if [ -n "$SLS_FUNC_URL" ]; then
      echo "  🔴 Function URL without authentication:" >> "$OUT"
      echo "$SLS_FUNC_URL" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
    fi

    # Permissive CORS
    SLS_CORS=$(grep -rnE "cors:\s*true" "$SLS_FILE" 2>/dev/null || true)
    if [ -n "$SLS_CORS" ]; then
      echo "  🟠 Permissive CORS (cors: true = origin: *):" >> "$OUT"
      echo "$SLS_CORS" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
    fi

    # Per-function IAM roles check
    if ! grep -qE "serverless-iam-roles-per-function|^\s{4,}iam:" "$SLS_FILE" 2>/dev/null; then
      echo "  🟠 Missing per-function IAM roles — all functions share one role" >> "$OUT"
    fi

    # HTTP endpoints without authorizer
    HTTP_EVENTS=$(grep -c -E "(http|httpApi):" "$SLS_FILE" 2>/dev/null || echo "0")
    AUTH_REFS=$(grep -c "authorizer" "$SLS_FILE" 2>/dev/null || echo "0")
    if [ "$HTTP_EVENTS" -gt 0 ] && [ "$AUTH_REFS" -eq 0 ]; then
      echo "  🔴 $HTTP_EVENTS HTTP endpoints without any authorizer" >> "$OUT"
    fi

    # serverless-offline in plugins
    if grep -qE "serverless-offline" "$SLS_FILE" 2>/dev/null; then
      echo "  🟠 serverless-offline plugin loaded (remove for production)" >> "$OUT"
    fi

    # serverless-dotenv-plugin
    if grep -qE "serverless-dotenv-plugin|useDotenv:\s*true" "$SLS_FILE" 2>/dev/null; then
      echo "  🟠 serverless-dotenv-plugin detected — ensure .env excluded from package" >> "$OUT"
    fi

    # Deprecated runtime
    SLS_OLD_RT=$(grep -rnE "runtime:\s*(nodejs12\.x|nodejs14\.x|nodejs16\.x)" "$SLS_FILE" 2>/dev/null || true)
    if [ -n "$SLS_OLD_RT" ]; then
      echo "  🟠 Deprecated Node.js runtime in serverless.yml:" >> "$OUT"
      echo "$SLS_OLD_RT" | head -3 | while read -r line; do echo "    $line" >> "$OUT"; done
    fi

    # Missing throttling
    if ! grep -qE "throttle:|burstLimit:|rateLimit:|reservedConcurrency:|serverless-api-gateway-throttling" "$SLS_FILE" 2>/dev/null; then
      echo "  🟡 Missing throttling/rate limiting configuration" >> "$OUT"
    fi

    # Missing deployment bucket encryption
    if ! grep -qE "serverSideEncryption:" "$SLS_FILE" 2>/dev/null; then
      echo "  🟡 Missing deployment bucket encryption" >> "$OUT"
    fi

    # Missing tracing
    if ! grep -qE "tracing:" "$SLS_FILE" 2>/dev/null; then
      echo "  🟡 Missing X-Ray tracing configuration" >> "$OUT"
    fi
  fi

  echo "" >> "$OUT"
fi

if [ "$USES_EXPRESS" = "false" ] && [ "$USES_KOA" = "false" ] && [ "$USES_WEBPACK" = "false" ] && [ "$USES_NESTJS" = "false" ] && [ "$USES_FASTIFY" = "false" ] && [ "$USES_BUN" = "false" ] && [ "$USES_LAMBDA" = "false" ] && [ "$USES_DOCKER" = "false" ] && [ "$USES_APPSYNC" = "false" ] && [ "$USES_TERRAFORM" = "false" ] && [ "$USES_CLOUDFORMATION" = "false" ] && [ "$USES_SERVERLESS" = "false" ]; then
  echo "  ℹ No supported frameworks or deployment targets detected" >> "$OUT"
  echo "" >> "$OUT"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$OUT"
echo "## Summary" >> "$OUT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$OUT"

CRITICAL_COUNT=$(grep -c "🔴" "$OUT" || echo "0")
WARN_COUNT=$(grep -c "⚠" "$OUT" || echo "0")
MEDIUM_COUNT=$(grep -c "🟡" "$OUT" || echo "0")
OK_COUNT=$(grep -c "✅" "$OUT" || echo "0")

echo "  🔴 Critical issues:  $CRITICAL_COUNT" >> "$OUT"
echo "  ⚠  Warnings:         $WARN_COUNT" >> "$OUT"
echo "  🟡 Medium issues:    $MEDIUM_COUNT" >> "$OUT"
echo "  ✅ Clean checks:     $OK_COUNT" >> "$OUT"
echo "" >> "$OUT"
echo "✅ Node.js version & built-in API audit complete. Results saved to $OUT" >> "$OUT"

cat "$OUT"
