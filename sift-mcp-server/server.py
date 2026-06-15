"""SIFT IR Agent — MCP server entry point.

Exposes 16 forensic tool functions over the MCP stdio transport so that
Claude Code (or any MCP-compatible agent) can call them as structured
typed functions rather than raw shell commands.

Architecture:
  Claude Code agent
       │ MCP stdio
       ▼
  server.py  (this file — FastMCP router)
       │ Python imports
       ▼
  tools/  (one module per evidence type)
       │ subprocess
       ▼
  SIFT forensic tools (volatility, evtx_dump, tshark, etc.)

Transport: stdio (spawned by Claude Code via .claude/settings.json)
No network listener — this server never binds a port.
"""

import functools
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from parsers import audit

# ── Evidence parsers ───────────────────────────────────────────────────────
from tools.volatility import (
    analyze_memory_processes,
    analyze_memory_network,
    analyze_memory_malfind,
)
from tools.evtx      import parse_event_logs
from tools.lotl      import hunt_lotl_behaviors
from tools.filesystem import analyze_disk_filesystem
from tools.carve     import carve_disk_artifacts
from tools.registry  import parse_registry_persistence
from tools.network   import analyze_network_capture
from tools.yara      import hunt_yara
from tools.timeline  import build_supertimeline
from tools.amcache   import parse_amcache
# Case-data read gateway (flat, audited reads for artifacts with no live-tool
# equivalent — precooked output, the Redline MANS DB, the evidence manifest).
from tools.casedata  import (
    read_case_artifact,
    search_case_artifact,
    query_mans,
    build_evidence_manifest,
)

# ── Server instance ────────────────────────────────────────────────────────
mcp = FastMCP(
    "sift-ir-agent",
    instructions=(
        "Autonomous incident response agent — SANS SIFT Workstation. "
        "Exposes 16 forensic analysis functions for memory, event logs, "
        "disk images, Amcache, network captures, and timeline correlation. "
        "All functions return structured JSON; raw tool output is "
        "saved to output_dir for the audit trail but never returned "
        "directly to the LLM."
    ),
)

# ── Audit wrapper ──────────────────────────────────────────────────────────
def audited(fn):
    """Wrap a tool so every call + result is written to the activity ledger.
    functools.wraps preserves the signature/docstring FastMCP introspects for
    the tool schema, so the typed interface is unchanged."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        token = audit.current_tool.set(fn.__name__)
        audit.log_event("call", fn=fn.__name__, args=audit.short_args(args, kwargs))
        try:
            result = fn(*args, **kwargs)
            err = result.get("error") if isinstance(result, dict) else None
            audit.log_event("result", fn=fn.__name__,
                            status="error" if err else "ok",
                            suspicious=(result.get("suspicious_count")
                                        if isinstance(result, dict) else None),
                            error=err)
            return result
        except Exception as exc:  # noqa: BLE001
            audit.log_event("result", fn=fn.__name__, status="error", error=str(exc))
            raise
        finally:
            audit.current_tool.reset(token)
    return wrapper


# ── Tool registry ──────────────────────────────────────────────────────────
TOOLS = [
    analyze_memory_processes, analyze_memory_network, analyze_memory_malfind,
    parse_event_logs, hunt_lotl_behaviors, analyze_disk_filesystem,
    carve_disk_artifacts, parse_registry_persistence, analyze_network_capture,
    hunt_yara, build_supertimeline, parse_amcache,
    # Case-data read gateway
    read_case_artifact, search_case_artifact, query_mans, build_evidence_manifest,
]
for _fn in TOOLS:
    mcp.tool()(audited(_fn))


def _write_manifest():
    """Emit the tool catalogue the dashboard's MCP panel reads (names + one-line
    descriptions). Written on startup so the panel reflects live capability."""
    path = Path(audit.AUDIT_LOG).parent / "mcp_manifest.json"
    tools = [{"name": f.__name__,
              "desc": (f.__doc__ or "").strip().splitlines()[0] if f.__doc__ else ""}
             for f in TOOLS]
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(
            {"server": "sift-ir-agent", "transport": "stdio", "tools": tools},
            indent=2))
    except Exception:
        pass


# ── Entry point ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    _write_manifest()
    # stdio transport — Claude Code spawns this process and communicates
    # via stdin/stdout. No port binding, no network exposure.
    mcp.run()
