"""Disk filesystem analyser — analyze_disk_filesystem MCP tool function.

Uses MFTECmd (EZ Tools) if available; falls back to fls (TSK).
Returns file listing with suspicious path highlighting: startup folders,
temp/writable paths, recently modified system binaries.

Based in part on marez8505/find-evil mft.py (MIT licence).
"""

import csv
import re
from pathlib import Path
from parsers.common import run_tool, save_raw_output, tool_missing_response

MAX_SUSPICIOUS = 300

# ── Paths that should not contain executables ──────────────────────────────
SUSPICIOUS_PATH_PATTERNS = [
    (
        r"\\(appdata\\local\\temp|temp|tmp|windows\\temp)\\.*\.(exe|dll|ps1|bat|vbs|hta|cmd|scr)",
        "Executable in temp directory",
        "T1204", "execution",
    ),
    (
        r"\\users\\public\\.*\.(exe|dll|ps1|bat|vbs|hta)",
        "Executable in Public user directory",
        "T1204", "execution",
    ),
    (
        r"\\start menu\\programs\\startup\\",
        "File in startup folder (persistence)",
        "T1547.001", "persistence",
    ),
    (
        r"\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\",
        "File in system-wide startup folder (persistence)",
        "T1547.001", "persistence",
    ),
    (
        r"\\windows\\(system32|syswow64)\\.*\.(ps1|bat|vbs|hta)",
        "Script in system32/syswow64",
        "T1036", "defense-evasion",
    ),
    (
        r"\\recycle\.bin\\|\\recycler\\",
        "Executable recovered from Recycle Bin",
        "T1070.004", "defense-evasion",
    ),
    (
        r"windows\\prefetch\\.*\.pf",
        "Prefetch file (evidence of execution)",
        "T1059", "execution",
    ),
    (
        r"\\windows\\system32\\tasks\\",
        "Scheduled task XML in Tasks directory",
        "T1053.005", "persistence",
    ),
]


def analyze_disk_filesystem(image_path: str, output_dir: str) -> dict:
    """Analyse disk image filesystem structure for suspicious entries.

    Uses MFTECmd (EZ Tools) preferentially for $MFT parsing; falls back
    to fls (TSK) for raw filesystem listing.

    Args:
        image_path: Path to disk image (.e01, .dd, .img) or mounted root
        output_dir: Write directory for raw output (audit trail)

    Returns:
        {
            tool, image_path, total_files_scanned, suspicious_count,
            suspicious: [ {path, size_bytes, created, modified, accessed,
                           reason, mitre_technique, kill_chain_stage,
                           confidence} ],
            error
        }
    """
    # ── Try MFTECmd on $MFT file ──
    mft_path = _find_mft(image_path)
    if mft_path:
        r = run_tool(
            ["MFTECmd", "-f", mft_path, "--csv", output_dir, "--csvf", "mft_parsed.csv"],
            timeout=300,
        )
        if not r["tool_missing"] and r["returncode"] == 0:
            return _parse_mftecmd_csv(output_dir, image_path)

    # ── Fallback: fls (TSK) ──
    r = run_tool(["fls", "-r", "-p", image_path], timeout=300)

    if r["tool_missing"]:
        return tool_missing_response(
            "fls / MFTECmd",
            "Install TSK: sudo apt-get install -y sleuthkit  "
            "or MFTECmd from https://ericzimmerman.github.io/",
        )

    save_raw_output(output_dir, "fls_recursive.txt", r["stdout"])
    return _parse_fls_output(r["stdout"], image_path)


# ── MFTECmd CSV parser ─────────────────────────────────────────────────────

def _parse_mftecmd_csv(output_dir: str, image_path: str) -> dict:
    csv_path = Path(output_dir) / "mft_parsed.csv"
    if not csv_path.exists():
        return {"error": "MFTECmd produced no CSV", "suspicious": [], "total_files_scanned": 0}

    suspicious: list[dict] = []
    total = 0

    with open(csv_path, newline="", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total += 1
            path = (row.get("ParentPath", "") + "\\" + row.get("FileName", "")).lower()

            for pattern, reason, technique, stage in SUSPICIOUS_PATH_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    suspicious.append({
                        "path":            path,
                        "size_bytes":      row.get("FileSize", ""),
                        "created":         row.get("Created0x10", ""),
                        "modified":        row.get("LastModified0x10", ""),
                        "accessed":        row.get("LastAccess0x10", ""),
                        "reason":          reason,
                        "mitre_technique": technique,
                        "kill_chain_stage": stage,
                        "confidence":      "medium",
                    })
                    break

            if len(suspicious) >= MAX_SUSPICIOUS:
                break

    return {
        "tool": "MFTECmd",
        "image_path": image_path,
        "total_files_scanned": total,
        "suspicious_count": len(suspicious),
        "suspicious": suspicious,
        "error": None,
    }


# ── fls fallback parser ────────────────────────────────────────────────────

def _parse_fls_output(stdout: str, image_path: str) -> dict:
    """Parse fls -r -p output (inode type path lines)."""
    suspicious: list[dict] = []
    total = 0

    for line in stdout.splitlines():
        # fls format: [d/d|r/r] inode-addr:   path
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        path = parts[-1].strip().lower()
        total += 1

        for pattern, reason, technique, stage in SUSPICIOUS_PATH_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                suspicious.append({
                    "path":            path,
                    "reason":          reason,
                    "mitre_technique": technique,
                    "kill_chain_stage": stage,
                    "confidence":      "medium",
                })
                break

        if len(suspicious) >= MAX_SUSPICIOUS:
            break

    return {
        "tool": "fls",
        "image_path": image_path,
        "total_files_scanned": total,
        "suspicious_count": len(suspicious),
        "suspicious": suspicious,
        "error": None,
    }


# ── helpers ────────────────────────────────────────────────────────────────

def _find_mft(image_path: str) -> str | None:
    """If image_path is a mounted directory, look for $MFT in its root."""
    p = Path(image_path)
    if p.is_dir():
        mft = p / "$MFT"
        return str(mft) if mft.exists() else None
    return None
