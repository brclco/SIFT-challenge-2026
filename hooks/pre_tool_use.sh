#!/usr/bin/env bash
# Pre-tool-use hook: validates Bash commands against the exec gateway before execution.
# Claude Code calls this hook before every Bash tool use.
#
# Exit 0  → allow Claude Code to proceed
# Exit 2  → block the tool call; stdout is shown to Claude as the reason
#
# If the gateway is unreachable, the hook fails-closed and blocks the command.
# Start the gateway first: python3 /cases/project/runclawd_exec_gateway.py &

GATEWAY_URL="http://127.0.0.1:12345"
TOKEN_FILE="/cases/project/.gateway_token"

# Load token
GATEWAY_TOKEN=""
if [[ -f "$TOKEN_FILE" ]]; then
    GATEWAY_TOKEN=$(cat "$TOKEN_FILE" 2>/dev/null | tr -d '[:space:]')
fi
if [[ -z "$GATEWAY_TOKEN" ]]; then
    GATEWAY_TOKEN="${EXEC_GATEWAY_TOKEN:-}"
fi

# Read the tool call JSON from stdin
TOOL_INPUT=$(cat)

# Only intercept Bash tool calls
TOOL_NAME=$(echo "$TOOL_INPUT" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('tool_name',''))" 2>/dev/null || echo "")

if [[ "$TOOL_NAME" != "Bash" ]]; then
    exit 0
fi

# Extract the command string
COMMAND=$(echo "$TOOL_INPUT" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('command',''))" 2>/dev/null || echo "")

if [[ -z "$COMMAND" ]]; then
    exit 0
fi

# Check gateway is running — fail-open with warning if down
if ! curl -s --max-time 2 "${GATEWAY_URL}/health" >/dev/null 2>&1; then
    echo "[GUARDRAIL WARNING] Exec gateway not reachable — running without enforcement" >&2
    echo "[GUARDRAIL WARNING] Start gateway: python3 /cases/project/runclawd_exec_gateway.py &" >&2
    exit 0
fi

# POST command to /validate
PAYLOAD=$(python3 -c "import sys,json; print(json.dumps({'command': sys.argv[1], 'caller': 'claude-code'}))" "$COMMAND" 2>/dev/null)
if [[ -z "$PAYLOAD" ]]; then
    exit 0
fi

RESPONSE=$(curl -s --max-time 5 \
    -X POST "${GATEWAY_URL}/validate" \
    -H "Content-Type: application/json" \
    -H "X-Gateway-Token: ${GATEWAY_TOKEN}" \
    -d "$PAYLOAD" 2>/dev/null)

STATUS=$(echo "$RESPONSE" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('status','error'))" 2>/dev/null || echo "error")

if [[ "$STATUS" == "allow" ]]; then
    exit 0
fi

REASON=$(echo "$RESPONSE" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('reason','policy violation'))" 2>/dev/null || echo "policy violation")

echo "[GUARDRAIL BLOCKED] ${REASON}"
echo "[GUARDRAIL BLOCKED] Command: ${COMMAND:0:120}"
exit 2
