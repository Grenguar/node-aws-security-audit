#!/usr/bin/env bash
# install.sh — Quick installer for nodejs-security-audit skill
# Usage: bash <(curl -fsSL https://raw.githubusercontent.com/Grenguar/node-aws-security-audit/main/install.sh)

set -euo pipefail

REPO="https://github.com/Grenguar/node-aws-security-audit.git"
SKILL_NAME="nodejs-security-audit"

echo ""
echo "  Node.js Security Audit Skill — Installer"
echo "  by Soroka Tech"
echo "  ──────────────────────────────────────────"
echo ""

# Detect available agents
AGENTS=()
PATHS=()

if [ -d "$HOME/.claude" ]; then
  AGENTS+=("Claude Code")
  PATHS+=("$HOME/.claude/skills/$SKILL_NAME")
fi
if [ -d "$HOME/.cursor" ]; then
  AGENTS+=("Cursor")
  PATHS+=("$HOME/.cursor/skills/$SKILL_NAME")
fi
if [ -d "$HOME/.agents" ]; then
  AGENTS+=("Codex")
  PATHS+=("$HOME/.agents/skills/$SKILL_NAME")
fi
if [ -d "$HOME/.codeium/windsurf" ]; then
  AGENTS+=("Windsurf")
  PATHS+=("$HOME/.codeium/windsurf/skills/$SKILL_NAME")
fi

if [ ${#AGENTS[@]} -eq 0 ]; then
  echo "  No supported AI agents detected."
  echo "  Installing to Claude Code default location..."
  AGENTS=("Claude Code")
  PATHS=("$HOME/.claude/skills/$SKILL_NAME")
fi

echo "  Detected agents:"
for i in "${!AGENTS[@]}"; do
  echo "    [$((i+1))] ${AGENTS[$i]} -> ${PATHS[$i]}"
done
echo "    [a] All detected agents"
echo ""

read -rp "  Install to which agent? [a]: " choice
choice="${choice:-a}"

install_skill() {
  local dest="$1"
  local agent="$2"

  if [ -d "$dest" ]; then
    echo "  Updating existing installation at $dest..."
    (cd "$dest" && git pull --ff-only 2>/dev/null) || {
      echo "  Could not pull updates. Removing and re-cloning..."
      rm -rf "$dest"
      git clone --depth 1 "$REPO" "$dest"
    }
  else
    mkdir -p "$(dirname "$dest")"
    git clone --depth 1 "$REPO" "$dest"
  fi

  chmod +x "$dest/scripts/"*.sh 2>/dev/null || true
  echo "  Installed to $agent: $dest"
}

echo ""

if [ "$choice" = "a" ]; then
  for i in "${!AGENTS[@]}"; do
    install_skill "${PATHS[$i]}" "${AGENTS[$i]}"
  done
else
  idx=$((choice - 1))
  if [ "$idx" -ge 0 ] && [ "$idx" -lt ${#AGENTS[@]} ]; then
    install_skill "${PATHS[$idx]}" "${AGENTS[$idx]}"
  else
    echo "  Invalid choice. Exiting."
    exit 1
  fi
fi

echo ""
echo "  Done! To run an audit, open your agent and type:"
echo ""
echo "    > audit my project for security vulnerabilities"
echo ""
echo "  Learn more: https://github.com/Grenguar/node-aws-security-audit"
echo "  Soroka Tech: https://sorokatech.com"
echo ""
