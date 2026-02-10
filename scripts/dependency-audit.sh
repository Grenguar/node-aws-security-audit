#!/usr/bin/env bash
# dependency-audit.sh — Collect dependency vulnerability data for the audit report.
# Outputs: dependency-audit-results.txt in the current directory.
#
# shellcheck disable=SC2129  # Individual redirects are clearer in this audit script

set -uo pipefail
# NOTE: Do NOT use set -e here. Commands like npm audit and npm outdated
# return non-zero exit codes when they find issues, which is expected behavior.

OUT="dependency-audit-results.txt"
echo "=== Node.js Dependency Security Audit ===" > "$OUT"
echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$OUT"
echo "" >> "$OUT"

# ── Locate package.json files ────────────────────────────────────────────────
MANIFESTS=$(find . -name "package.json" -not -path "*/node_modules/*" -maxdepth 4 2>/dev/null)

if [ -z "$MANIFESTS" ]; then
  echo "ERROR: No package.json found in the project." >> "$OUT"
  cat "$OUT"
  exit 0
fi

while IFS= read -r PKG; do
  DIR="$(dirname "$PKG")"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$OUT"
  echo "📦 Package: $PKG" >> "$OUT"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$OUT"
  echo "" >> "$OUT"

  # ── Node and npm versions ───────────────────────────────────────────────
  echo "## Environment" >> "$OUT"
  node --version 2>/dev/null >> "$OUT" || echo "node: not found" >> "$OUT"
  npm --version 2>/dev/null | xargs -I{} echo "npm: {}" >> "$OUT" || echo "npm: not found" >> "$OUT"
  echo "" >> "$OUT"

  # ── Engine constraints ──────────────────────────────────────────────────
  echo "## Engine requirements" >> "$OUT"
  node -e "
    const pkg = require(process.argv[1]);
    if (pkg.engines) {
      Object.entries(pkg.engines).forEach(([k, v]) => console.log(k + ': ' + v));
    } else {
      console.log('No engine constraints specified (potential risk).');
    }
  " "./$PKG" 2>/dev/null >> "$OUT" || echo "Could not parse engines." >> "$OUT"
  echo "" >> "$OUT"

  # ── npm audit ───────────────────────────────────────────────────────────
  if [ -f "$DIR/node_modules/.package-lock.json" ] || [ -f "$DIR/package-lock.json" ] || [ -f "$DIR/yarn.lock" ]; then
    echo "## npm audit" >> "$OUT"
    (cd "$DIR" && npm audit --json 2>/dev/null) >> "$OUT" || {
      echo "npm audit exited with warnings (see above)." >> "$OUT"
    }
    echo "" >> "$OUT"

    echo "## npm audit (human-readable summary)" >> "$OUT"
    (cd "$DIR" && npm audit 2>&1) >> "$OUT" || true
    echo "" >> "$OUT"
  else
    echo "## npm audit" >> "$OUT"
    echo "⚠ No lockfile found. Run 'npm install' first, then re-run this script." >> "$OUT"
    echo "" >> "$OUT"
  fi

  # ── Outdated packages ──────────────────────────────────────────────────
  echo "## Outdated packages" >> "$OUT"
  (cd "$DIR" && npm outdated 2>&1) >> "$OUT" || true
  echo "" >> "$OUT"

  # ── Dependency count ───────────────────────────────────────────────────
  echo "## Dependency counts" >> "$OUT"
  node -e "
    const pkg = require(process.argv[1]);
    const deps = Object.keys(pkg.dependencies || {}).length;
    const devDeps = Object.keys(pkg.devDependencies || {}).length;
    console.log('Production dependencies: ' + deps);
    console.log('Dev dependencies:        ' + devDeps);
    console.log('Total:                   ' + (deps + devDeps));
  " "./$PKG" 2>/dev/null >> "$OUT" || echo "Could not count dependencies." >> "$OUT"
  echo "" >> "$OUT"

  # ── Check for wildcard / unpinned versions ─────────────────────────────
  echo "## Unpinned or wildcard versions" >> "$OUT"
  node -e "
    const pkg = require(process.argv[1]);
    const all = { ...pkg.dependencies, ...pkg.devDependencies };
    const risky = Object.entries(all).filter(([, v]) =>
      v === '*' || v === 'latest' || v.startsWith('>=') || v === ''
    );
    if (risky.length) {
      risky.forEach(([name, ver]) => console.log('  ⚠ ' + name + ': ' + ver));
    } else {
      console.log('  ✅ All versions are pinned or use semver ranges.');
    }
  " "./$PKG" 2>/dev/null >> "$OUT" || echo "Could not check versions." >> "$OUT"
  echo "" >> "$OUT"

  # ── Check for known risky packages ─────────────────────────────────────
  echo "## Known risky or deprecated packages" >> "$OUT"
  node -e "
    const pkg = require(process.argv[1]);
    const all = { ...pkg.dependencies, ...pkg.devDependencies };
    const names = Object.keys(all);
    const flagged = names.filter(n =>
      n === 'node-serialize' ||
      n === 'csurf' ||
      n === 'request' ||
      n === 'node-uuid' ||
      (n === 'mathjs' && all[n].match(/^[<^~]?0\./))
    );
    if (flagged.length) {
      flagged.forEach(n => console.log('  ⚠ ' + n + ' — consider replacing with modern alternative'));
    } else {
      console.log('  ✅ No commonly flagged packages detected.');
    }
  " "./$PKG" 2>/dev/null >> "$OUT" || echo "Could not check risky packages." >> "$OUT"
  echo "" >> "$OUT"

done <<< "$MANIFESTS"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$OUT"
echo "✅ Dependency audit complete. Results saved to $OUT" >> "$OUT"

cat "$OUT"
