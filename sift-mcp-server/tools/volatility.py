"""Volatility 3 memory analysis — three MCP tool functions.

analyze_memory_processes  — process tree + command lines, parent-child flags
analyze_memory_network    — netscan, external connection flags
analyze_memory_malfind    — injected code / hollowed process detection

Based in part on marez8505/find-evil volatility.py (MIT licence).
"""

import re
from parsers.common import run_tool, save_raw_output, tool_missing_response, is_private_ip

# ── Suspicious parent → child sets ────────────────────────────────────────
SUSPICIOUS_PARENTS: dict[str, set[str]] = {
    "winword.exe":   {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "excel.exe":     {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "outlook.exe":   {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "powerpnt.exe":  {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
    "chrome.exe":    {"powershell.exe", "cmd.exe"},
    "firefox.exe":   {"powershell.exe", "cmd.exe"},
    "msedge.exe":    {"powershell.exe", "cmd.exe"},
    "lsass.exe":     {"cmd.exe", "powershell.exe", "net.exe"},
    "spoolsv.exe":   {"cmd.exe", "powershell.exe"},
    "svchost.exe":   {"powershell.exe", "cmd.exe"},   # svchost rarely spawns user shells
}

WRITABLE_PATH_RE = re.compile(
    r"(\\temp\\|\\tmp\\|\\appdata\\local\\temp\\|\\users\\public\\|\\programdata\\)",
    re.IGNORECASE,
)

INSTALL_HINT = "pip3 install volatility3"


# ── analyze_memory_processes ──────────────────────────────────────────────

def analyze_memory_processes(image_path: str, output_dir: str) -> dict:
    """Analyse running processes from a memory image using Volatility 3.

    Runs windows.pstree and windows.cmdline. Flags anomalous parent-child
    pairs and processes executing from temp/writable paths.

    Args:
        image_path: Absolute path to memory image (.vmem / .raw / .mem)
        output_dir: Write directory for raw output (audit trail)

    Returns:
        {
            tool, image, total_processes, suspicious_count,
            suspicious: [ {pid, ppid, name, parent_name, cmdline,
                           reason, mitre_technique, kill_chain_stage,
                           confidence} ],
            error
        }
    """
    # ── pstree ──
    pt = run_tool(["vol", "-f", image_path, "-q", "windows.pstree"], timeout=180)
    if pt["tool_missing"]:
        return tool_missing_response("Volatility 3 (vol)", INSTALL_HINT)
    save_raw_output(output_dir, "vol_pstree.txt", pt["stdout"])

    # ── cmdline ──
    cl = run_tool(["vol", "-f", image_path, "-q", "windows.cmdline"], timeout=180)
    save_raw_output(output_dir, "vol_cmdline.txt", cl["stdout"])

    # Build PID → cmdline map
    cmdlines: dict[int, str] = {}
    for line in cl["stdout"].splitlines():
        parts = line.strip().split("\t")
        if len(parts) >= 3:
            try:
                cmdlines[int(parts[0])] = parts[2].strip()
            except ValueError:
                pass

    # Build PID → name map (for parent lookup)
    pid_to_name: dict[int, str] = {}
    for line in pt["stdout"].splitlines():
        p = _parse_pstree_line(line)
        if p:
            pid_to_name[p["pid"]] = p["name"].lower()

    # Score each process
    suspicious: list[dict] = []
    total = 0

    for line in pt["stdout"].splitlines():
        p = _parse_pstree_line(line)
        if not p:
            continue
        total += 1

        name   = p["name"].lower()
        parent = pid_to_name.get(p["ppid"], "").lower()
        cmd    = cmdlines.get(p["pid"], "")

        entry: dict = {
            "pid": p["pid"], "ppid": p["ppid"],
            "name": p["name"], "parent_name": parent or "unknown",
            "cmdline": cmd[:300],
        }

        if name in SUSPICIOUS_PARENTS.get(parent, set()):
            entry.update(
                reason=f"{parent} spawning {name}",
                mitre_technique="T1059",
                kill_chain_stage="execution",
                confidence="high",
            )
            suspicious.append(entry)
        elif WRITABLE_PATH_RE.search(cmd):
            entry.update(
                reason="Process executing from temp/writable path",
                mitre_technique="T1204",
                kill_chain_stage="execution",
                confidence="medium",
            )
            suspicious.append(entry)

    return {
        "tool": "volatility3/windows.pstree+cmdline",
        "image": image_path,
        "total_processes": total,
        "suspicious_count": len(suspicious),
        "suspicious": suspicious,
        "error": pt["stderr"] if pt["returncode"] != 0 else None,
    }


def _parse_pstree_line(line: str) -> dict | None:
    """Parse one volatility pstree line → {pid, ppid, name} or None."""
    parts = line.strip().split()
    if len(parts) < 3:
        return None
    try:
        return {"pid": int(parts[0]), "ppid": int(parts[1]), "name": parts[2]}
    except ValueError:
        return None


# ── analyze_memory_network ─────────────────────────────────────────────────

def analyze_memory_network(image_path: str, output_dir: str) -> dict:
    """Extract network connections from memory using Volatility 3 netscan.

    Flags connections from unexpected processes to non-RFC-1918 addresses.

    Args:
        image_path: Absolute path to memory image
        output_dir: Write directory for raw output

    Returns:
        {
            tool, image, total_connections, suspicious_count,
            suspicious: [ {offset, proto, local_addr, foreign_addr,
                           state, pid, owner, reason, mitre_technique,
                           kill_chain_stage, confidence} ],
            error
        }
    """
    r = run_tool(["vol", "-f", image_path, "-q", "windows.netscan"], timeout=180)
    if r["tool_missing"]:
        return tool_missing_response("Volatility 3 (vol)", INSTALL_HINT)
    save_raw_output(output_dir, "vol_netscan.txt", r["stdout"])

    # Processes that commonly make external connections — lower suspicion threshold
    EXPECTED_EXTERNAL = {
        "svchost.exe", "system", "searchindexer.exe",
        "msmpeng.exe", "msiexec.exe", "wuauclt.exe",
    }

    connections: list[dict] = []
    suspicious:  list[dict] = []

    for line in r["stdout"].splitlines():
        parts = line.strip().split()
        # Header / blank lines
        if len(parts) < 6 or parts[0] in ("Offset", "#", ""):
            continue
        try:
            entry = {
                "offset":       parts[0],
                "proto":        parts[1],
                "local_addr":   parts[2],
                "foreign_addr": parts[3],
                "state":        parts[4],
                "pid":          parts[5],
                "owner":        parts[6] if len(parts) > 6 else "?",
            }
            foreign_ip = entry["foreign_addr"].split(":")[0]

            if (
                not is_private_ip(foreign_ip)
                and entry["owner"].lower() not in EXPECTED_EXTERNAL
            ):
                entry.update(
                    reason=f"External connection from {entry['owner']} → {foreign_ip}",
                    mitre_technique="T1071",
                    kill_chain_stage="command-and-control",
                    confidence="medium",
                )
                suspicious.append(entry)

            connections.append(entry)
        except IndexError:
            continue

    return {
        "tool": "volatility3/windows.netscan",
        "image": image_path,
        "total_connections": len(connections),
        "suspicious_count": len(suspicious),
        "suspicious": suspicious,
        "error": r["stderr"] if r["returncode"] != 0 else None,
    }


# ── analyze_memory_malfind ─────────────────────────────────────────────────

def analyze_memory_malfind(image_path: str, output_dir: str) -> dict:
    """Detect injected code regions using Volatility 3 malfind.

    MZ headers found outside normal image-load locations indicate code
    injection (T1055) or process hollowing (T1055.012).

    Args:
        image_path: Absolute path to memory image
        output_dir: Write directory for raw output

    Returns:
        {
            tool, image, suspicious_count,
            suspicious: [ {process, pid, address, vad_tag,
                           has_mz_header, reason, mitre_technique,
                           kill_chain_stage, confidence} ],
            error
        }
    """
    r = run_tool(["vol", "-f", image_path, "-q", "windows.malfind"], timeout=300)
    if r["tool_missing"]:
        return tool_missing_response("Volatility 3 (vol)", INSTALL_HINT)
    save_raw_output(output_dir, "vol_malfind.txt", r["stdout"])

    suspicious: list[dict] = []
    current:    dict       = {}

    for line in r["stdout"].splitlines():
        line = line.strip()

        if not line:
            if current:
                suspicious.append(current)
                current = {}
            continue

        if line.startswith("Process:"):
            parts = line.split()
            current = {
                "process":         parts[1] if len(parts) > 1 else "?",
                "pid":             parts[3] if len(parts) > 3 else "?",
                "has_mz_header":   False,
                "mitre_technique": "T1055",
                "kill_chain_stage":"defense-evasion",
                "confidence":      "medium",
                "reason":          "Injected memory region (no MZ header)",
            }
        elif line.startswith("VAD") or "VadTag" in line:
            current["vad_tag"] = line[:120]
        elif re.search(r"(0x4d5a|MZ\s)", line, re.IGNORECASE) or line[:2] in ("MZ",):
            current["has_mz_header"] = True
            current["confidence"]    = "high"
            current["reason"]        = "MZ header in injected region — likely code injection or hollowing"
            current["mitre_technique"] = "T1055.012"

    if current:
        suspicious.append(current)

    return {
        "tool": "volatility3/windows.malfind",
        "image": image_path,
        "suspicious_count": len(suspicious),
        "suspicious": suspicious,
        "error": r["stderr"] if r["returncode"] != 0 else None,
    }
