"""Amcache artefact parser — parse_amcache MCP tool function.

Parses Amcache.hve (Windows AppCompat) to enumerate recently executed
programs. Uses AmcacheParser (EZ Tools) as primary; falls back to
RegRipper with the amcache plugin.

Amcache.hve is typically at:
    Windows\AppCompat\Programs\Amcache.hve

Key signals for IR:
  - Programs executed from temp / writable / user-profile paths
  - Unknown executables with no publisher (unsigned)
  - LOL binaries appearing at unusual paths
  - Programs deleted after execution (present in Amcache, absent on disk)

Closes the gap vs marez8505/find-evil — not present in that repo.
"""

import csv
import re
from pathlib import Path
from parsers.common import run_tool, save_raw_output, tool_missing_response

MAX_SUSPICIOUS = 200

INSTALL_HINT = (
    "AmcacheParser not found. Install EZ Tools .NET suite: "
    "https://ericzimmerman.github.io/ "
    "(requires dotnet 6 on Linux: sudo apt-get install -y dotnet-runtime-6.0). "
    "Fallback: sudo apt-get install -y libregf-utils  # for regripper amcache plugin"
)

# ── Suspicious execution path patterns ────────────────────────────────────
SUSPICIOUS_PATH_PATTERNS: list[tuple[str, str, str, str]] = [
    (
        r"\\(temp|tmp|appdata\\local\\temp)\\.*\.(exe|dll|ps1|bat|scr|com)",
        "Executable executed from temp directory",
        "T1204", "execution",
    ),
    (
        r"\\users\\public\\.*\.(exe|dll|ps1|bat|vbs|hta)",
        "Executable executed from Public user directory",
        "T1204", "execution",
    ),
    (
        r"\\users\\[^\\]+\\(downloads|desktop)\\.*\.(exe|dll)",
        "Executable executed from Downloads or Desktop",
        "T1204", "execution",
    ),
    (
        r"\\(recycle\.bin|recycler)\\",
        "Executable executed from Recycle Bin",
        "T1070.004", "defense-evasion",
    ),
    (
        r"\\(programdata|appdata)\\.*\.(ps1|bat|vbs|hta|cmd|js|jse|wsf)",
        "Script executed from ProgramData or AppData",
        "T1059", "execution",
    ),
    (
        r"\\windows\\(temp|tasks)\\.*\.(exe|dll)",
        "Executable executed from Windows\\Temp or Tasks",
        "T1204", "execution",
    ),
]

# LOL binaries — execution logged in Amcache is significant IR signal
LOLBAS_NAMES: set[str] = {
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
    "wmic.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
    "msiexec.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "msbuild.exe", "odbcconf.exe", "ieexec.exe", "mavinject.exe",
    "msdt.exe", "pcalua.exe", "syncappvpublishingserver.exe",
    "xwizard.exe", "runscripthelper.exe",
}


def parse_amcache(hive_path: str, output_dir: str) -> dict:
    """Parse Amcache.hve to enumerate program execution history.

    Amcache.hve records recently executed programs with SHA-1 hash,
    full path, and timestamps. Useful for detecting execution from
    suspicious locations, unsigned executables, and programs deleted
    after running (present in Amcache but absent on disk).

    Args:
        hive_path: Path to Amcache.hve (e.g. extracted from disk image)
        output_dir: Write directory for raw output (audit trail)

    Returns:
        {
            tool, hive_path,
            total_entries, suspicious_count,
            suspicious: [ {name, path, sha1, timestamp,
                           publisher, reason, mitre_technique,
                           kill_chain_stage, confidence} ],
            deleted_executables: [ {name, path, sha1} ],
            error
        }
    """
    if not Path(hive_path).exists():
        return {
            "error": f"Amcache.hve not found: {hive_path}",
            "suspicious": [], "total_entries": 0,
        }

    # ── Primary: AmcacheParser (EZ Tools) ──────────────────────────────
    r = run_tool(
        ["AmcacheParser", "-f", hive_path,
         "--csv", output_dir, "--csvf", "amcache_parsed.csv",
         "-q"],           # -q suppresses progress output
        timeout=120,
    )

    if not r["tool_missing"] and r["returncode"] == 0:
        save_raw_output(output_dir, "amcacheparser_stderr.txt", r["stderr"])
        return _parse_amcacheparser_csv(output_dir, hive_path)

    # ── Fallback: RegRipper amcache plugin ─────────────────────────────
    r2 = run_tool(
        ["regripper", "-r", hive_path, "-p", "amcache"],
        timeout=60,
    )

    if r2["tool_missing"]:
        return tool_missing_response("AmcacheParser / regripper amcache", INSTALL_HINT)

    save_raw_output(output_dir, "regripper_amcache.txt", r2["stdout"])
    return _parse_regripper_output(r2["stdout"], hive_path)


# ── AmcacheParser CSV parser ───────────────────────────────────────────────

def _parse_amcacheparser_csv(output_dir: str, hive_path: str) -> dict:
    """Parse AmcacheParser UnassociatedFileEntries CSV output."""
    # AmcacheParser writes files named: <prefix>_UnassociatedFileEntries.csv
    # The prefix is derived from the hive filename + timestamp
    out = Path(output_dir)
    csv_files = list(out.glob("*UnassociatedFileEntries*.csv"))
    if not csv_files:
        # Fall back to any CSV produced
        csv_files = list(out.glob("amcache_parsed*.csv"))
    if not csv_files:
        return {
            "error": "AmcacheParser produced no CSV output",
            "suspicious": [], "total_entries": 0,
            "tool": "AmcacheParser",
        }

    csv_path = csv_files[0]
    suspicious:  list[dict] = []
    deleted:     list[dict] = []
    total = 0

    with open(csv_path, newline="", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total += 1
            path      = (row.get("FullPath") or row.get("Path") or "").lower()
            name      = (row.get("Name")     or Path(path).name if path else "").lower()
            sha1      = row.get("SHA1") or row.get("Hash", "")
            ts        = row.get("FileKeyLastWriteTimestamp") or row.get("LastModifiedDateTimeUtc", "")
            publisher = row.get("Publisher") or row.get("CompanyName", "")

            if not path:
                continue

            # Check if file still exists on the mounted image (best-effort)
            if not Path(path).exists() and sha1:
                deleted.append({"name": name, "path": path, "sha1": sha1})

            # Suspicious path patterns
            matched = False
            for pattern, reason, technique, stage in SUSPICIOUS_PATH_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    suspicious.append({
                        "name":            name,
                        "path":            path,
                        "sha1":            sha1,
                        "timestamp":       ts,
                        "publisher":       publisher,
                        "reason":          reason,
                        "mitre_technique": technique,
                        "kill_chain_stage": stage,
                        "confidence":      "high",
                    })
                    matched = True
                    break

            if not matched:
                # LOL binary at any path is worth flagging
                if name in LOLBAS_NAMES:
                    suspicious.append({
                        "name":            name,
                        "path":            path,
                        "sha1":            sha1,
                        "timestamp":       ts,
                        "publisher":       publisher,
                        "reason":          f"LOL binary execution logged in Amcache: {name}",
                        "mitre_technique": "T1218",
                        "kill_chain_stage": "defense-evasion",
                        "confidence":      "medium",
                    })
                # Unsigned executable (no publisher) outside system dirs
                elif (not publisher
                      and name.endswith(".exe")
                      and not re.search(r"\\windows\\(system32|syswow64|winsxs)\\", path)):
                    suspicious.append({
                        "name":            name,
                        "path":            path,
                        "sha1":            sha1,
                        "timestamp":       ts,
                        "publisher":       "",
                        "reason":          "Unsigned/unknown-publisher executable",
                        "mitre_technique": "T1036",
                        "kill_chain_stage": "defense-evasion",
                        "confidence":      "low",
                    })

            if len(suspicious) >= MAX_SUSPICIOUS:
                break

    return {
        "tool":            "AmcacheParser",
        "hive_path":       hive_path,
        "csv_path":        str(csv_path),
        "total_entries":   total,
        "suspicious_count": len(suspicious),
        "suspicious":      suspicious,
        "deleted_executables": deleted[:50],
        "error":           None,
    }


# ── RegRipper fallback parser ──────────────────────────────────────────────

def _parse_regripper_output(stdout: str, hive_path: str) -> dict:
    """Parse RegRipper amcache plugin text output.

    RegRipper amcache output format (approximate):
        amcache v.20200427
        (Amcache.hve)
        SHA1: <hash>
        Path: <path>
        LastMod: <timestamp>
        ...
    """
    suspicious: list[dict] = []
    total = 0

    # Parse entry blocks separated by blank lines
    current: dict = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            if current.get("path"):
                total += 1
                _score_regripper_entry(current, suspicious)
                current = {}
            continue

        if line.startswith("SHA1:"):
            current["sha1"] = line.split(":", 1)[1].strip()
        elif line.startswith("Path:") or line.startswith("path:"):
            current["path"] = line.split(":", 1)[1].strip().lower()
            current["name"] = Path(current["path"]).name.lower()
        elif line.startswith("LastMod:") or line.startswith("LastWrite:"):
            current["timestamp"] = line.split(":", 1)[1].strip()
        elif line.startswith("Publisher:") or line.startswith("Company:"):
            current["publisher"] = line.split(":", 1)[1].strip()

    # Handle last entry
    if current.get("path"):
        total += 1
        _score_regripper_entry(current, suspicious)

    return {
        "tool":            "regripper/amcache",
        "hive_path":       hive_path,
        "total_entries":   total,
        "suspicious_count": len(suspicious),
        "suspicious":      suspicious[:MAX_SUSPICIOUS],
        "deleted_executables": [],
        "error":           None,
    }


def _score_regripper_entry(entry: dict, suspicious: list[dict]) -> None:
    """Apply suspicious-path and LOL-binary scoring to one parsed entry."""
    path      = entry.get("path", "")
    name      = entry.get("name", "")
    sha1      = entry.get("sha1", "")
    ts        = entry.get("timestamp", "")
    publisher = entry.get("publisher", "")

    for pattern, reason, technique, stage in SUSPICIOUS_PATH_PATTERNS:
        if re.search(pattern, path, re.IGNORECASE):
            suspicious.append({
                "name": name, "path": path, "sha1": sha1,
                "timestamp": ts, "publisher": publisher,
                "reason": reason, "mitre_technique": technique,
                "kill_chain_stage": stage, "confidence": "high",
            })
            return

    if name in LOLBAS_NAMES:
        suspicious.append({
            "name": name, "path": path, "sha1": sha1,
            "timestamp": ts, "publisher": publisher,
            "reason": f"LOL binary execution logged in Amcache: {name}",
            "mitre_technique": "T1218",
            "kill_chain_stage": "defense-evasion",
            "confidence": "medium",
        })
