#!/usr/bin/env bash
# SessionStart hook: ensure the exec gateway is running for every Claude Code
# session. Idempotent — the /health probe prevents duplicate instances, and the
# gateway is started fully detached (setsid) so it survives this session and is
# present for future ones. Never blocks session start (always exits 0).
#
# Runs as a harness hook, so it is NOT subject to the Bash-tool allowlist (same
# as pre_tool_use.sh, which also uses curl).

GATEWAY_URL="http://127.0.0.1:12345"
AUDIT="${EXEC_GATEWAY_AUDIT_LOG:-/home/la/analysis/exec_gateway_audit.log}"
OUT="/home/la/analysis/exec_gateway.out"
GATEWAY="/cases/project/runclawd_exec_gateway.py"

# Already up? nothing to do.
if curl -s --max-time 2 "${GATEWAY_URL}/health" >/dev/null 2>&1; then
    exit 0
fi

# Start detached so it outlives this session.
mkdir -p /home/la/analysis 2>/dev/null
if command -v setsid >/dev/null 2>&1; then
    EXEC_GATEWAY_AUDIT_LOG="$AUDIT" setsid python3 "$GATEWAY" >>"$OUT" 2>&1 < /dev/null &
else
    EXEC_GATEWAY_AUDIT_LOG="$AUDIT" nohup python3 "$GATEWAY" >>"$OUT" 2>&1 < /dev/null &
fi
disown 2>/dev/null || true
exit 0
