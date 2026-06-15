#!/usr/bin/env bash
#
# Find Evil! — one-click installer for the SANS SIFT Workstation.
#
#   curl -fsSL https://raw.githubusercontent.com/brclco/SIFT-challenge-2026/main/install.sh | bash
#
# What it does (idempotent, non-destructive):
#   1. checks prerequisites (git, python3)
#   2. clones/updates the repo into $FINDEVIL_HOME (default ~/find-evil)
#   3. installs the Python dependencies
#   4. registers the sift-ir-agent MCP server in your MCP config (merges; backs up first)
#   5. starts the exec gateway (forensic mode) if one isn't already running
#   6. prints the remaining wiring + how to run
#
# It never overwrites ~/.claude/settings.json (that controls your agent's permissions);
# it prints the hook snippet to add. Everything is overridable via env vars (see below),
# which is how the test harness runs it in an isolated prefix.
#
set -euo pipefail

REPO_URL="${FINDEVIL_REPO:-https://github.com/brclco/SIFT-challenge-2026.git}"
INSTALL_DIR="${FINDEVIL_HOME:-$HOME/find-evil}"
MCP_CONFIG="${FINDEVIL_MCP_CONFIG:-$HOME/.mcp.json}"
PY="${PYTHON:-python3}"
SKIP_GATEWAY="${FINDEVIL_SKIP_GATEWAY:-0}"
GATEWAY_URL="http://127.0.0.1:12345"

c_g='\033[1;32m'; c_y='\033[1;33m'; c_r='\033[1;31m'; c_0='\033[0m'
log()  { printf "${c_g}[find-evil]${c_0} %s\n" "$*"; }
warn() { printf "${c_y}[find-evil]${c_0} %s\n" "$*" >&2; }
die()  { printf "${c_r}[find-evil]${c_0} %s\n" "$*" >&2; exit 1; }

# ── 1. prerequisites ─────────────────────────────────────────────────────────
command -v git >/dev/null 2>&1 || die "git not found — install git and re-run."
command -v "$PY" >/dev/null 2>&1 || die "$PY not found — install Python 3 and re-run."
log "using $($PY --version 2>&1) and $(git --version)"

# ── 2. clone or update ───────────────────────────────────────────────────────
if [ -d "$INSTALL_DIR/.git" ]; then
  log "updating existing checkout at $INSTALL_DIR"
  git -C "$INSTALL_DIR" pull --ff-only --quiet || warn "could not fast-forward; leaving checkout as-is"
else
  log "cloning $REPO_URL -> $INSTALL_DIR"
  git clone --depth 1 --quiet "$REPO_URL" "$INSTALL_DIR" || die "git clone failed"
fi

# ── 3. python dependencies (best-effort; non-fatal) ──────────────────────────
if [ "${FINDEVIL_SKIP_DEPS:-0}" = "1" ]; then
  log "skipping dependency install (FINDEVIL_SKIP_DEPS=1)"
else
  log "installing Python dependencies"
  reqs="$INSTALL_DIR/sift-mcp-server/requirements.txt"
  pip_install() { "$PY" -m pip install --user -q "$@" 2>/dev/null \
               || "$PY" -m pip install --user -q --break-system-packages "$@" 2>/dev/null; }
  if [ -f "$reqs" ]; then
    pip_install -r "$reqs" || warn "some requirements failed to install — check sift-mcp-server/requirements.txt"
  fi
  pip_install flask reportlab || warn "flask/reportlab may already be present or need manual install"
fi

# ── 4. register the MCP server (merge + backup) ──────────────────────────────
log "registering the sift-ir-agent MCP server in $MCP_CONFIG"
if [ -f "$MCP_CONFIG" ]; then
  cp "$MCP_CONFIG" "${MCP_CONFIG}.bak.$$" && log "backed up existing config -> ${MCP_CONFIG}.bak.$$"
fi
INSTALL_DIR="$INSTALL_DIR" MCP_CONFIG="$MCP_CONFIG" "$PY" - <<'PYEOF'
import json, os
install_dir = os.environ["INSTALL_DIR"]
cfg = os.environ["MCP_CONFIG"]
server = {
    "type": "stdio",
    "command": "python3",
    "args": [os.path.join(install_dir, "sift-mcp-server", "server.py")],
    "env": {"PYTHONPATH": os.path.join(install_dir, "sift-mcp-server")},
}
data = {}
if os.path.exists(cfg):
    try:
        with open(cfg) as f:
            data = json.load(f)
    except Exception:
        data = {}
data.setdefault("mcpServers", {})["sift-ir-agent"] = server
os.makedirs(os.path.dirname(cfg) or ".", exist_ok=True)
with open(cfg, "w") as f:
    json.dump(data, f, indent=2)
print("  mcpServers.sift-ir-agent ->", server["args"][0])
PYEOF

# ── 5. start the exec gateway (forensic mode) if not already up ──────────────
if [ "$SKIP_GATEWAY" = "1" ]; then
  log "skipping gateway start (FINDEVIL_SKIP_GATEWAY=1)"
elif command -v curl >/dev/null 2>&1 && curl -s --max-time 2 "$GATEWAY_URL/health" >/dev/null 2>&1; then
  log "exec gateway already running at $GATEWAY_URL"
else
  log "starting exec gateway (forensic mode)"
  gw="$INSTALL_DIR/gateway/runclawd_exec_gateway.py"
  if [ -f "$gw" ]; then
    if command -v setsid >/dev/null 2>&1; then
      setsid "$PY" "$gw" >>"$INSTALL_DIR/gateway.out" 2>&1 < /dev/null &
    else
      nohup "$PY" "$gw" >>"$INSTALL_DIR/gateway.out" 2>&1 < /dev/null &
    fi
    disown 2>/dev/null || true
    sleep 1
    if command -v curl >/dev/null 2>&1 && curl -s --max-time 2 "$GATEWAY_URL/health" >/dev/null 2>&1; then
      log "gateway is up at $GATEWAY_URL"
    else
      warn "gateway did not respond yet — check $INSTALL_DIR/gateway.out"
    fi
  else
    warn "gateway script not found at $gw"
  fi
fi

# ── 6. next steps ────────────────────────────────────────────────────────────
cat <<EOF

$(printf "${c_g}[find-evil]${c_0}") install complete. Repo: $INSTALL_DIR

Next steps:
  1. Wire the agent's guardrail hooks into your agent client settings (e.g.
     ~/.claude/settings.json) — add the PreToolUse(Bash) and SessionStart hooks
     and the permission deny-list from:  $INSTALL_DIR/agent/settings.json
     (we do NOT auto-edit your settings; review and merge it yourself).
  2. Add a case:   mkdir -p /cases/<CASE>/evidence  (place evidence here, read-only)
  3. Dashboard:    $PY $INSTALL_DIR/web/dashboard.py --case /cases/<CASE> --host 127.0.0.1 --port 5000
  4. PDF report:   $PY $INSTALL_DIR/analysis-scripts/generate_report.py --case /cases/<CASE>

Try it against public evidence (NIST CFReDS "Data Leakage Case"): see docs/TRY_IT_OUT.md
EOF
