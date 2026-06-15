"""Activity ledger for the SIFT MCP server.

Every MCP tool call and every underlying OS subprocess is appended as one JSON
object per line to SIFT_MCP_AUDIT_LOG. The dashboard's "MCP Server Activity"
panel tails this file. This is the MCP analogue of the exec-gateway audit log:
  kind="call"   — an agent invoked an MCP tool function
  kind="exec"   — that tool then ran a forensic binary via run_tool()
  kind="result" — the tool returned (ok / error, suspicious count)
"""

import json
import os
import contextvars
from datetime import datetime, timezone
from pathlib import Path

AUDIT_LOG = Path(os.environ.get("SIFT_MCP_AUDIT_LOG",
                                "/home/la/analysis/mcp_server_audit.log"))

# the tool function currently executing — lets run_tool() attribute OS execs
current_tool: "contextvars.ContextVar[str]" = contextvars.ContextVar(
    "current_tool", default="?")


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def short_args(args: tuple, kwargs: dict) -> str:
    """Compact, path-shortened summary of a tool call's arguments."""
    items = dict(kwargs)
    for i, a in enumerate(args):
        items[f"arg{i}"] = a
    parts = []
    for k, v in items.items():
        s = str(v)
        if "/" in s or "\\" in s:
            s = os.path.basename(s.rstrip("/\\")) or s
        parts.append(f"{k}={s[:48]}")
    return ", ".join(parts)


def log_event(kind: str, **fields) -> None:
    """Append one ledger record. Never raises (logging must not break analysis)."""
    rec = {"ts": _ts(), "kind": kind, **fields}
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass
