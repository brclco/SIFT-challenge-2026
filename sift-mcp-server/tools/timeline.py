"""Supertimeline builder — build_supertimeline MCP tool function.

Runs log2timeline.py (Plaso) to build a .plaso database from all evidence
sources, then exports with psort.py to CSV. Returns a bounded slice of the
most suspicious timeline entries — not the full CSV.

New function — not present in marez8505/find-evil.
"""

import csv
import re
from pathlib import Path
from parsers.common import run_tool, save_raw_output, tool_missing_response

MAX_ENTRIES = 500

INSTALL_HINT = (
    "log2timeline.py not found. "
    "Install Plaso: sudo apt-get install -y python3-plaso  "
    "or pip3 install plaso"
)

# ── Suspicious timeline patterns ──────────────────────────────────────────
# Applied to the 'message' column of psort CSV output
SUSPICIOUS_TIMELINE_PATTERNS: list[tuple[str, str, str, str]] = [
    (
        r"(powershell|cmd\.exe|mshta|wscript|cscript).{0,80}(-enc|/c\s|http)",
        "Scripting/LOL binary with suspicious arguments in timeline",
        "T1059", "execution",
    ),
    (
        r"\\start menu\\programs\\startup\\",
        "File written to startup folder",
        "T1547.001", "persistence",
    ),
    (
        r"(certutil|bitsadmin).{0,60}(urlcache|transfer|http)",
        "Download cradle activity in timeline",
        "T1105", "execution",
    ),
    (
        r"delete\s+shadows|vssadmin.{0,30}delete",
        "VSS shadow copy deletion",
        "T1490", "impact",
    ),
    (
        r"(\\temp\\|\\tmp\\|appdata\\local\\temp\\).{0,60}\.(exe|dll|ps1|bat)",
        "Executable written to temp directory",
        "T1204", "execution",
    ),
    (
        r"(registry|software\\microsoft\\windows\\currentversion\\run)",
        "Registry run-key modification in timeline",
        "T1547.001", "persistence",
    ),
    (
        r"security.evtx.*cleared|log\s+cleared",
        "Security log cleared",
        "T1070.001", "defense-evasion",
    ),
    (
        r"scheduled.task|schtasks",
        "Scheduled task activity in timeline",
        "T1053.005", "persistence",
    ),
]


def build_supertimeline(evidence_dir: str, output_dir: str,
                        filter_date: str = "") -> dict:
    """Build a supertimeline from all evidence in evidence_dir using Plaso.

    Step 1 — log2timeline.py: parses all supported artefacts in evidence_dir
             and writes case.plaso.
    Step 2 — psort.py: exports to CSV, optionally filtered by date range.
    Step 3 — Returns bounded slice of suspicious timeline entries.

    Args:
        evidence_dir: Directory containing disk image, memory, evtx, pcap
        output_dir:   Write directory for .plaso and CSV (audit trail)
        filter_date:  Optional psort date filter e.g. "2024-01-15T00:00:00
                      TO 2024-01-16T00:00:00"

    Returns:
        {
            tool, evidence_dir, plaso_path, csv_path,
            total_entries, suspicious_count,
            suspicious: [ {datetime, source, source_type, message,
                           reason, mitre_technique, kill_chain_stage,
                           confidence} ],
            error
        }
    """
    plaso_path = str(Path(output_dir) / "case.plaso")
    csv_path   = str(Path(output_dir) / "timeline.csv")

    # ── Step 1: log2timeline ──
    log2tl = run_tool(
        ["log2timeline.py", "--status_view", "none",
         "--storage_file", plaso_path, evidence_dir],
        timeout=1800,   # 30 min — Plaso can be slow on large images
    )

    if log2tl["tool_missing"]:
        return tool_missing_response("log2timeline.py (Plaso)", INSTALL_HINT)

    save_raw_output(output_dir, "log2timeline_stderr.txt", log2tl["stderr"])

    if log2tl["returncode"] not in (0, 1) or not Path(plaso_path).exists():
        return {
            "error": f"log2timeline failed: {log2tl['stderr'][:500]}",
            "suspicious": [], "total_entries": 0,
        }

    # ── Step 2: psort export to CSV ──
    psort_cmd = [
        "psort.py", "-o", "l2tcsv",
        "-w", csv_path,
        plaso_path,
    ]
    if filter_date:
        psort_cmd += ["--slice", filter_date]

    psort = run_tool(psort_cmd, timeout=600)
    save_raw_output(output_dir, "psort_stderr.txt", psort["stderr"])

    if not Path(csv_path).exists():
        return {
            "error": f"psort produced no CSV: {psort['stderr'][:500]}",
            "suspicious": [], "total_entries": 0,
            "plaso_path": plaso_path,
        }

    # ── Step 3: score entries ──
    suspicious, total = _score_timeline_csv(csv_path)

    return {
        "tool": "plaso/log2timeline+psort",
        "evidence_dir": evidence_dir,
        "plaso_path": plaso_path,
        "csv_path": csv_path,
        "total_entries": total,
        "suspicious_count": len(suspicious),
        "suspicious": suspicious[:MAX_ENTRIES],
        "error": None,
    }


# ── CSV scorer ─────────────────────────────────────────────────────────────

def _score_timeline_csv(csv_path: str) -> tuple[list[dict], int]:
    """Read psort l2tcsv and return (suspicious_entries, total_count)."""
    suspicious: list[dict] = []
    total = 0

    with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total += 1
            # l2tcsv has no "message" column; its text lives in desc/short.
            message = (row.get("message") or row.get("Message")
                       or row.get("desc") or row.get("short") or "").lower()
            if not message:
                continue

            for pattern, reason, technique, stage in SUSPICIOUS_TIMELINE_PATTERNS:
                if re.search(pattern, message, re.IGNORECASE):
                    suspicious.append({
                        "datetime":        row.get("datetime") or row.get("timestamp", ""),
                        "source":          row.get("source") or row.get("Source", ""),
                        "source_type":     row.get("source_long") or row.get("SourceType", ""),
                        "message":         message[:400],
                        "reason":          reason,
                        "mitre_technique": technique,
                        "kill_chain_stage": stage,
                        "confidence":      "medium",
                    })
                    break

    return suspicious, total
