#!/usr/bin/env bash
# test-patterns.sh — Verify security audit grep patterns against fixtures
set -uo pipefail

PASS=0
FAIL=0
FIXTURES_DIR="$(cd "$(dirname "$0")/fixtures" && pwd)"

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

echo "=== Security Pattern Tests ==="
echo ""

# --- Tests against vulnerable.js (should match) ---
echo "## Patterns that SHOULD match vulnerable.js"

# Test: eval detection
if grep -qE '\beval\s*\(' "$FIXTURES_DIR/vulnerable.js"; then
  pass "eval() detected"
else
  fail "eval() not detected"
fi

# Test: hardcoded secret
if grep -qE '(JWT_SECRET|password|secret|api_key)\s*[:=]\s*['"'"'"][^'"'"'"]{4,}' "$FIXTURES_DIR/vulnerable.js"; then
  pass "hardcoded secret detected"
else
  fail "hardcoded secret not detected"
fi

# Test: MD5 usage
if grep -qE "createHash\(['\"]md5['\"]\)" "$FIXTURES_DIR/vulnerable.js"; then
  pass "MD5 hashing detected"
else
  fail "MD5 hashing not detected"
fi

# Test: exec() command injection
if grep -qE '\bexec\(' "$FIXTURES_DIR/vulnerable.js"; then
  pass "exec() detected"
else
  fail "exec() not detected"
fi

# Test: vm module
if grep -qE "require\(['\"]vm['\"]\)" "$FIXTURES_DIR/vulnerable.js"; then
  pass "vm module detected"
else
  fail "vm module not detected"
fi

# Test: Buffer constructor
if grep -qE 'new Buffer\(' "$FIXTURES_DIR/vulnerable.js"; then
  pass "unsafe Buffer detected"
else
  fail "unsafe Buffer not detected"
fi

# Test: url.parse
if grep -qE "url\.parse\(" "$FIXTURES_DIR/vulnerable.js" 2>/dev/null; then
  pass "legacy url.parse detected"
else
  fail "legacy url.parse not detected"
fi

# Test: querystring module
if grep -qE "require\(['\"]querystring['\"]\)" "$FIXTURES_DIR/vulnerable.js"; then
  pass "deprecated querystring detected"
else
  fail "deprecated querystring not detected"
fi

# Test: node-serialize
if grep -qE "node-serialize" "$FIXTURES_DIR/vulnerable.js"; then
  pass "node-serialize detected"
else
  fail "node-serialize not detected"
fi

# Test: console.log with request body
if grep -qE "console\.log\(req\.body\)" "$FIXTURES_DIR/vulnerable.js"; then
  pass "PII logging detected"
else
  fail "PII logging not detected"
fi

# Test: SSRF via fetch with user input
if grep -qE "fetch\(req\." "$FIXTURES_DIR/vulnerable.js"; then
  pass "SSRF via fetch detected"
else
  fail "SSRF via fetch not detected"
fi

echo ""

# --- Tests against secure.js (should NOT match) ---
echo "## Patterns that should NOT match secure.js"

# Test: eval should not match secure code
if grep -qE '\beval\s*\(' "$FIXTURES_DIR/secure.js"; then
  fail "false positive: eval in secure.js"
else
  pass "no eval false positive"
fi

# Test: MD5 should not match sha256
if grep -qE "createHash\(['\"]md5['\"]\)" "$FIXTURES_DIR/secure.js"; then
  fail "false positive: MD5 in secure.js"
else
  pass "no MD5 false positive"
fi

# Test: exec should not match execFile
if grep -E '\bexec\(' "$FIXTURES_DIR/secure.js" | grep -qv "execFile"; then
  fail "false positive: exec in secure.js"
else
  pass "no exec false positive"
fi

# Test: Buffer.alloc should not match
if grep -qE 'new Buffer\(' "$FIXTURES_DIR/secure.js"; then
  fail "false positive: unsafe Buffer in secure.js"
else
  pass "no Buffer false positive"
fi

# Test: url.parse should not match new URL
if grep -qE 'url\.parse\(' "$FIXTURES_DIR/secure.js"; then
  fail "false positive: url.parse in secure.js"
else
  pass "no url.parse false positive"
fi

# Test: querystring should not match URLSearchParams
if grep -qE "require\(['\"]querystring['\"]\)" "$FIXTURES_DIR/secure.js"; then
  fail "false positive: querystring in secure.js"
else
  pass "no querystring false positive"
fi

echo ""
echo "=== Results ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "FAILED — $FAIL test(s) did not pass"
  exit 1
else
  echo "ALL TESTS PASSED"
  exit 0
fi
