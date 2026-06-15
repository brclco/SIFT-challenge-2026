"""Windows registry persistence parser — parse_registry_persistence MCP tool.

Uses RECmd (EZ Tools) if available; falls back to RegRipper.
Focused on persistence key locations. Includes ClickFix-specific patterns
in run-key value data.

Based in part on marez8505/find-evil registry.py (MIT licence).
"""

import csv
import re
import subprocess
from pathlib import Path
from parsers.common import run_tool, save_raw_output, tool_missing_response

# ── Persistence key paths (RECmd batch filter) ─────────────────────────────
PERSISTENCE_KEYS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",          # AppInit_DLLs
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"SYSTEM\CurrentControlSet\Services",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
]

# ── Suspicious value-data patterns ────────────────────────────────────────
# (regex, reason, MITRE technique, kill-chain stage)
SUSPICIOUS_PATTERNS: list[tuple[str, str, str, str]] = [
    (
        r"powershell.{0,40}(-enc|-encodedcommand|-e\s+[A-Za-z0-9+/]{10})",
        "Encoded PowerShell in registry persistence key (ClickFix indicator)",
        "T1547.001", "persistence",
    ),
    (
        r"(-nop|-noprofile).{0,60}(-w\s*h|-windowstyle\s*hidden)",
        "Hidden PowerShell window via registry run key",
        "T1547.001", "persistence",
    ),
    (
        r"(mshta|wscript|cscript).{0,80}\.(vbs|js|hta)",
        "Script interpreter in persistence run key",
        "T1547.001", "persistence",
    ),
    (
        r"(certutil|bitsadmin).{0,80}https?://",
        "Download cradle in persistence run key",
        "T1547.001", "persistence",
    ),
    (
        r"(appdata|temp|tmp|users\\public).{0,60}\.(exe|dll|ps1|bat|cmd)",
        "Executable from writable path in persistence run key",
        "T1547.001", "persistence",
    ),
    (
        r"(IEX|Invoke-Expression).{0,80}(http|Download|Net\.WebClient)",
        "PowerShell download cradle in persistence run key",
        "T1547.001", "persistence",
    ),
    (
        r"cmd\.exe.{0,20}/c.{0,80}(powershell|mshta|wscript)",
        "CMD launching interpreter from run key",
        "T1547.001", "persistence",
    ),
    # Winlogon hijacking
    (
        r"(Userinit|Shell)\s*=.{0,200}(cmd|powershell|\.exe)",
        "Winlogon Userinit or Shell key modified — potential hijack",
        "T1547.004", "persistence",
    ),
    # IFEO debugger hijacking
    (
        r"Debugger\s*=",
        "Image File Execution Options Debugger key set",
        "T1546.012", "persistence",
    ),
]

MAX_ENTRIES = 300


def parse_registry_persistence(hive_dir: str, output_dir: str) -> dict:
    """Parse Windows registry hives for persistence mechanisms.

    Covers Run/RunOnce, Winlogon, IFEO, Services, AppInit_DLLs, Shell Folders.
    Includes ClickFix-specific pattern detection in run-key value data.

    Args:
        hive_dir: Path to Windows\\System32\\config\\ directory (from mounted
                  image) or directory containing extracted hive files
                  (SOFTWARE, SYSTEM, NTUSER.DAT).
        output_dir: Write directory for raw CSV output (audit trail)

    Returns:
        {
            tool, hive_dir, total_entries, suspicious_count,
            persistence_entries: [ {key_path, value_name, value_data,
                                    hive, last_write_time,
                                    suspicious, reason, mitre_technique,
                                    kill_chain_stage, confidence} ],
            suspicious: [ same shape, only flagged entries ],
            error
        }
    """
    hive_path = Path(hive_dir)
    if not hive_path.exists():
        return {"error": f"hive_dir does not exist: {hive_dir}",
                "suspicious": [], "persistence_entries": []}

    # ── Try RECmd (EZ Tools) ──
    recmd_result = run_tool(
        ["RECmd", "-d", hive_dir,
         "--bn", _write_recmd_batch(output_dir),
         "--csv", output_dir, "--csvf", "registry_persistence.csv"],
        timeout=120,
    )

    if not recmd_result["tool_missing"] and recmd_result["returncode"] == 0:
        return _parse_recmd_csv(output_dir, hive_dir)

    # ── Fallback: RegRipper ──
    return _run_regripper(hive_dir, output_dir)


# ── RECmd helpers ──────────────────────────────────────────────────────────

def _write_recmd_batch(output_dir: str) -> str:
    """Write a RECmd batch file scoped to persistence keys. Returns path."""
    batch_path = Path(output_dir) / "persistence_batch.reb"
    lines = ["Description: IR persistence key batch", "Author: sift-ir-agent", ""]
    for key in PERSISTENCE_KEYS:
        lines.append(f'HiveType:Any|Category:Persistence|KeyPath:{key}|Recursive:true|Comment:""')
    batch_path.write_text("\n".join(lines))
    return str(batch_path)


def _parse_recmd_csv(output_dir: str, hive_dir: str) -> dict:
    csv_path = Path(output_dir) / "registry_persistence.csv"
    if not csv_path.exists():
        return {"error": "RECmd produced no CSV", "suspicious": [], "persistence_entries": []}

    entries:   list[dict] = []
    suspicious: list[dict] = []

    with open(csv_path, newline="", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            value_data = row.get("ValueData", "") or ""
            susp, reason, technique, stage = _score_value(value_data)

            entry = {
                "key_path":        row.get("KeyPath", ""),
                "value_name":      row.get("ValueName", ""),
                "value_data":      value_data[:500],
                "hive":            row.get("HiveType", ""),
                "last_write_time": row.get("LastWriteTimestamp", ""),
                "suspicious":      susp,
                "reason":          reason,
                "mitre_technique": technique,
                "kill_chain_stage": stage,
                "confidence":      "high" if susp else "low",
            }
            entries.append(entry)
            if susp:
                suspicious.append(entry)
            if len(entries) >= MAX_ENTRIES:
                break

    return {
        "tool": "RECmd",
        "hive_dir": hive_dir,
        "total_entries": len(entries),
        "suspicious_count": len(suspicious),
        "persistence_entries": entries,
        "suspicious": suspicious,
        "error": None,
    }


# ── RegRipper fallback ─────────────────────────────────────────────────────

REGRIPPER_PLUGINS = ["run", "autoruns", "winlogon", "services", "appinitdlls", "ifeo"]


def _run_regripper(hive_dir: str, output_dir: str) -> dict:
    hive_path = Path(hive_dir)

    # Locate hive files (case-insensitive)
    hive_files = {
        f.name.lower(): f
        for f in hive_path.rglob("*")
        if f.is_file() and f.suffix.lower() in ("", ".dat")
           and f.name.lower() in (
               "software", "system", "ntuser.dat", "sam", "security"
           )
    }

    if not hive_files:
        return tool_missing_response(
            "RECmd / RegRipper",
            "Install RECmd from https://ericzimmerman.github.io/ "
            "or RegRipper: sudo apt-get install regripper",
        )

    entries:   list[dict] = []
    suspicious: list[dict] = []
    errors = []

    for hive_name, hive_file in hive_files.items():
        for plugin in REGRIPPER_PLUGINS:
            r = run_tool(
                ["regripper", "-r", str(hive_file), "-p", plugin],
                timeout=60,
            )
            if r["tool_missing"]:
                errors.append("RegRipper not found")
                break
            if r["returncode"] != 0:
                continue

            save_raw_output(output_dir, f"regripper_{hive_name}_{plugin}.txt", r["stdout"])

            for block in r["stdout"].split("\n\n"):
                if not block.strip():
                    continue
                susp, reason, technique, stage = _score_value(block)
                entry = {
                    "key_path":        _extract_key_path(block),
                    "value_data":      block[:500],
                    "hive":            hive_name,
                    "plugin":          plugin,
                    "suspicious":      susp,
                    "reason":          reason,
                    "mitre_technique": technique,
                    "kill_chain_stage": stage,
                    "confidence":      "high" if susp else "low",
                }
                entries.append(entry)
                if susp:
                    suspicious.append(entry)
                if len(entries) >= MAX_ENTRIES:
                    break

    return {
        "tool": "RegRipper",
        "hive_dir": hive_dir,
        "total_entries": len(entries),
        "suspicious_count": len(suspicious),
        "persistence_entries": entries,
        "suspicious": suspicious,
        "error": "; ".join(errors) if errors else None,
    }


# ── shared helpers ─────────────────────────────────────────────────────────

def _score_value(value: str) -> tuple[bool, str, str, str]:
    for pattern, reason, technique, stage in SUSPICIOUS_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return True, reason, technique, stage
    return False, "", "", ""


def _extract_key_path(block: str) -> str:
    for line in block.splitlines():
        if "\\" in line and ("Software" in line or "System" in line):
            return line.strip()[:200]
    return ""
