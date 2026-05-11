#!/usr/bin/env bash
# pre-commit-hook.sh — entry point for the pre-commit framework.
# Runs security-audit on staged changes and blocks the commit if a finding
# at or above $SECURITY_AUDIT_FAIL_ON severity is detected.
#
# Environment:
#   ANTHROPIC_API_KEY              required (looks in env, then ~/.config/security-audit/key)
#   SECURITY_AUDIT_FAIL_ON         severity gate (default: critical)
#   SECURITY_AUDIT_MODEL           model alias (default: sonnet)
#   SECURITY_AUDIT_SKIP=1          bypass entirely
#
# Standard pre-commit framework conventions:
#   - exit 0 → commit proceeds
#   - exit !=0 → commit blocked

set -e

if [ "${SECURITY_AUDIT_SKIP:-0}" = "1" ]; then
  echo "[security-audit] SECURITY_AUDIT_SKIP=1 — skipping scan."
  exit 0
fi

# Locate the hook entry irrespective of repo layout
HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$HOOK_DIR/.." && pwd)"

# Fall back to a per-user API key file if env is not set
if [ -z "$ANTHROPIC_API_KEY" ] && [ -f "$HOME/.config/security-audit/key" ]; then
  ANTHROPIC_API_KEY="$(cat "$HOME/.config/security-audit/key" | tr -d '[:space:]')"
  export ANTHROPIC_API_KEY
fi

if [ -z "$ANTHROPIC_API_KEY" ]; then
  cat >&2 <<EOF
[security-audit] ANTHROPIC_API_KEY not set. Skipping security review.
  Set it in your shell, or save it to ~/.config/security-audit/key.
  To bypass without configuring, set SECURITY_AUDIT_SKIP=1.
EOF
  exit 0
fi

FAIL_ON="${SECURITY_AUDIT_FAIL_ON:-critical}"
MODEL="${SECURITY_AUDIT_MODEL:-sonnet}"

echo "[security-audit] Reviewing staged changes (fail-on=$FAIL_ON, model=$MODEL)..."

# Run the scan against staged changes
if node "$REPO_DIR/scripts/scan_diff.mjs" \
     --staged \
     --model="$MODEL" \
     --fail-on="$FAIL_ON" \
     --format=cli \
     --no-color; then
  echo "[security-audit] Clean."
  exit 0
else
  RC=$?
  if [ "$RC" = "2" ]; then
    echo >&2 "[security-audit] BLOCKING: at least one finding at or above '$FAIL_ON'."
    echo >&2 "  - Address the issue, or add 'security-audit-ignore: <rule_id> — <reason>' on the line above."
    echo >&2 "  - To bypass once: SECURITY_AUDIT_SKIP=1 git commit ..."
    exit "$RC"
  fi
  echo >&2 "[security-audit] Tool error (exit $RC)."
  exit "$RC"
fi
