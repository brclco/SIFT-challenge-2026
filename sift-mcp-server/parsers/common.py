"""Shared subprocess utilities for SIFT MCP server tool wrappers.

Every tool wrapper uses run_tool() for subprocess execution and
save_raw_output() to write raw tool output to the audit trail directory.
All timestamps are UTC ISO-8601.
"""

import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── SIFT tool-path resolver ────────────────────────────────────────────────
# Single source of truth for how each logical tool is invoked on THIS box.
# Verified against the live filesystem on 2026-06-13 (not from stale docs):
#   * Volatility 3 lives in a venv at /opt/volatility3/bin/vol — bare `vol`
#     on PATH is Volatility 2 and must NOT be used.
#   * EZ Tools are .NET DLLs run via the dotnet runtime (no SDK).
# Tools already on PATH (fls, icat, log2timeline.py, psort.py, bulk_extractor)
# are left as-is. Tools NOT installed here (tshark, evtx_dump, regripper) are
# left bare so run_tool() reports tool_missing and the caller can fall back.
TOOLMAP: dict[str, list[str]] = {
    "vol":                  ["/opt/volatility3/bin/vol"],
    "EvtxECmd":             ["dotnet", "/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll"],
    "RECmd":                ["dotnet", "/opt/zimmermantools/RECmd/RECmd.dll"],
    "MFTECmd":              ["dotnet", "/opt/zimmermantools/MFTECmd.dll"],
    "AmcacheParser":        ["dotnet", "/opt/zimmermantools/AmcacheParser.dll"],
    "AppCompatCacheParser": ["dotnet", "/opt/zimmermantools/AppCompatCacheParser.dll"],
    "yara":                 ["/usr/local/bin/yara"],
    "chainsaw":             ["/usr/local/bin/chainsaw"],
}


def resolve_cmd(cmd: list[str]) -> list[str]:
    """Expand a logical tool name (cmd[0]) to its real SIFT invocation."""
    if cmd and cmd[0] in TOOLMAP:
        return TOOLMAP[cmd[0]] + [str(c) for c in cmd[1:]]
    return cmd


def run_tool(
    cmd: list[str],
    timeout: int = 300,
    cwd: Optional[str] = None,
    input_data: Optional[str] = None,
) -> dict:
    """Run a forensic binary and return a structured result; log it to the ledger."""
    out = _run_tool_impl(cmd, timeout, cwd, input_data)
    try:
        from parsers import audit
        status = ("missing" if out.get("tool_missing")
                  else "timeout" if out.get("timed_out")
                  else "ok" if out.get("returncode") == 0 else "error")
        audit.log_event("exec", fn=audit.current_tool.get(),
                        command=out.get("cmd", ""), status=status,
                        exit_code=out.get("returncode"), sha256=out.get("sha256", ""))
    except Exception:
        pass
    return out


def _run_tool_impl(
    cmd: list[str],
    timeout: int = 300,
    cwd: Optional[str] = None,
    input_data: Optional[str] = None,
) -> dict:
    """Run a subprocess command and return a structured result dict.

    Never raises — all errors are captured and returned in the result.

    Returns:
        {
            stdout:     str,
            stderr:     str,
            returncode: int,
            cmd:        str,        # space-joined command for audit log
            sha256:     str,        # SHA-256 of stdout
            timestamp:  str,        # UTC ISO-8601
            timed_out:  bool,
            tool_missing: bool,     # True when binary not found
        }
    """
    now = datetime.now(timezone.utc).isoformat()
    cmd = resolve_cmd(cmd)
    cmd_str = " ".join(str(c) for c in cmd)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            input=input_data,
        )
        stdout = result.stdout or ""
        return {
            "stdout": stdout,
            "stderr": result.stderr or "",
            "returncode": result.returncode,
            "cmd": cmd_str,
            "sha256": hashlib.sha256(stdout.encode()).hexdigest(),
            "timestamp": now,
            "timed_out": False,
            "tool_missing": False,
        }

    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": f"Timed out after {timeout}s",
            "returncode": -1,
            "cmd": cmd_str,
            "sha256": "",
            "timestamp": now,
            "timed_out": True,
            "tool_missing": False,
        }

    except FileNotFoundError:
        return {
            "stdout": "",
            "stderr": f"Binary not found: {cmd[0]}",
            "returncode": -1,
            "cmd": cmd_str,
            "sha256": "",
            "timestamp": now,
            "timed_out": False,
            "tool_missing": True,
        }

    except Exception as exc:  # noqa: BLE001
        return {
            "stdout": "",
            "stderr": str(exc),
            "returncode": -1,
            "cmd": cmd_str,
            "sha256": "",
            "timestamp": now,
            "timed_out": False,
            "tool_missing": False,
        }


def save_raw_output(output_dir: str, filename: str, content: str) -> str:
    """Write raw tool output to the audit trail directory.

    Creates output_dir (and parents) if it does not exist.
    Returns the absolute path of the file written.
    """
    path = Path(output_dir) / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", errors="replace")
    return str(path)


def tool_missing_response(tool_name: str, install_hint: str) -> dict:
    """Standard structured error when a required tool is not installed."""
    return {
        "error": f"{tool_name} not found. {install_hint}",
        "tool_available": False,
        "suspicious": [],
        "findings": [],
    }


def is_private_ip(ip: str) -> bool:
    """Return True if the IPv4 address is RFC-1918, loopback, or link-local."""
    if not ip or ip in ("*", "", "::", "0.0.0.0"):
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return True  # IPv6 or invalid — don't flag
    try:
        a, b = int(parts[0]), int(parts[1])
        return (
            a == 10
            or a == 127
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or (a == 169 and b == 254)
        )
    except ValueError:
        return True
