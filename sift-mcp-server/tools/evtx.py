"""Windows event log parser — parse_event_logs MCP tool function.

Uses EvtxECmd (EZ Tools) if available, falls back to evtx_dump.
Filters to key security event IDs and applies suspicious pattern detection.

Based in part on marez8505/find-evil evtx.py (MIT licence).
"""

import csv
import json
import re
from pathlib import Path
from parsers.common import run_tool, save_raw_output, tool_missing_response

# ── Key event IDs ──────────────────────────────────────────────────────────
KEY_EVENT_IDS: dict[int, str] = {
    4624: "Logon success",
    4625: "Logon failure",
    4648: "Explicit credential use (Pass-the-Hash indicator)",
    4688: "Process creation",
    4698: "Scheduled task created",
    4702: "Scheduled task modified",
    4720: "User account created",
    4732: "User added to security group",
    4740: "Account locked out",
    7045: "New service installed",
    1102: "Security audit log cleared",
    4104: "PowerShell script block logged",
    4103: "PowerShell module logging",
}

# ── Suspicious payload patterns ────────────────────────────────────────────
# (regex, human reason, MITRE technique, kill-chain stage)
SUSPICIOUS_PATTERNS: list[tuple[str, str, str, str]] = [
    (
        r"powershell.{0,30}(-enc|-encodedcommand|-e\s+[A-Za-z0-9+/]{10})",
        "Encoded PowerShell command",
        "T1059.001", "execution",
    ),
    (
        r"(-nop|-noprofile).{0,50}(-w\s*h|-windowstyle\s*hidden)",
        "Hidden PowerShell window",
        "T1059.001", "defense-evasion",
    ),
    (
        r"(certutil|bitsadmin|mshta|regsvr32|wmic|cscript|wscript).{0,60}https?://",
        "LOL binary downloading from web",
        "T1105", "execution",
    ),
    (
        r"cmd\.exe.{0,20}/c.{0,50}powershell",
        "CMD spawning PowerShell",
        "T1059.001", "execution",
    ),
    (
        r"net\s+(user|localgroup|group).{0,40}(admin|administrator)",
        "Account or group manipulation",
        "T1136", "persistence",
    ),
    (
        r"schtasks.{0,20}/create",
        "Scheduled task creation",
        "T1053.005", "persistence",
    ),
    (
        r"reg\s+(add|delete).{0,60}(run|startup|currentversion)",
        "Registry run-key manipulation",
        "T1547.001", "persistence",
    ),
    (
        r"(IEX|Invoke-Expression|Invoke-Command).{0,80}(http|Download)",
        "PowerShell download cradle",
        "T1059.001", "execution",
    ),
]

MAX_KEY_EVENTS = 500   # output bound — never return more than this


def parse_event_logs(evtx_path: str, output_dir: str) -> dict:
    """Parse Windows event log (.evtx) and return key security events.

    Tries EvtxECmd (EZ Tools) first; falls back to evtx_dump.
    Filters to KEY_EVENT_IDS and scores events against SUSPICIOUS_PATTERNS.

    Args:
        evtx_path: Path to a .evtx file or directory of .evtx files
        output_dir: Write directory for raw/CSV output (audit trail)

    Returns:
        {
            tool, artifact, total_key_events, suspicious_count,
            key_events: [ {event_id, description, time, computer,
                           payload_preview, suspicious, reason,
                           mitre_technique, kill_chain_stage,
                           confidence} ],
            suspicious: [ same shape, only flagged entries ],
            error
        }
    """
    # ── Try EvtxECmd ──
    # EvtxECmd uses -f for a single .evtx file and -d for a directory of them;
    # passing -f with a directory silently parses nothing (returns 0 events).
    ecmd_flag = "-d" if Path(evtx_path).is_dir() else "-f"
    ecmd_result = run_tool(
        ["EvtxECmd", ecmd_flag, evtx_path,
         "--csv", output_dir, "--csvf", "evtx_parsed.csv"],
        timeout=300,
    )

    if not ecmd_result["tool_missing"] and ecmd_result["returncode"] == 0:
        return _parse_evtxecmd_csv(output_dir, evtx_path)

    # ── Fallback: evtx_dump ──
    dump_result = run_tool(
        ["evtx_dump", "--format", "json", evtx_path],
        timeout=120,
    )

    if dump_result["tool_missing"]:
        return tool_missing_response(
            "evtx_dump / EvtxECmd",
            "Install evtx_dump: pip3 install evtx  "
            "or EZ Tools EvtxECmd from https://ericzimmerman.github.io/",
        )

    save_raw_output(output_dir, "evtx_dump.jsonl", dump_result["stdout"])
    return _parse_evtx_dump_jsonl(dump_result["stdout"], evtx_path)


# ── parsers ────────────────────────────────────────────────────────────────

def _score_payload(payload: str) -> tuple[bool, str, str, str]:
    """Return (suspicious, reason, technique, stage) for a payload string."""
    for pattern, reason, technique, stage in SUSPICIOUS_PATTERNS:
        if re.search(pattern, payload, re.IGNORECASE):
            return True, reason, technique, stage
    return False, "", "", ""


def _parse_evtxecmd_csv(output_dir: str, artifact: str) -> dict:
    csv_path = Path(output_dir) / "evtx_parsed.csv"
    if not csv_path.exists():
        return {
            "error": "EvtxECmd ran but produced no CSV output",
            "suspicious": [], "key_events": [],
        }

    key_events: list[dict] = []
    suspicious: list[dict] = []

    with open(csv_path, newline="", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                eid = int(row.get("EventId", 0))
            except ValueError:
                continue
            if eid not in KEY_EVENT_IDS:
                continue

            payload = row.get("Payload", "") or row.get("MapDescription", "")
            susp, reason, technique, stage = _score_payload(payload)

            entry = {
                "event_id":    eid,
                "description": KEY_EVENT_IDS[eid],
                "time":        row.get("TimeCreated", ""),
                "computer":    row.get("Computer", ""),
                "payload_preview": payload[:400],
                "suspicious":  susp,
                "reason":      reason,
                "mitre_technique": technique,
                "kill_chain_stage": stage,
                "confidence":  "high" if susp else "low",
            }
            key_events.append(entry)
            if susp:
                suspicious.append(entry)
            if len(key_events) >= MAX_KEY_EVENTS:
                break

    return {
        "tool": "EvtxECmd",
        "artifact": artifact,
        "total_key_events": len(key_events),
        "suspicious_count": len(suspicious),
        "key_events": key_events,
        "suspicious": suspicious,
        "error": None,
    }


def _parse_evtx_dump_jsonl(stdout: str, artifact: str) -> dict:
    key_events: list[dict] = []
    suspicious: list[dict] = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        try:
            eid = int(
                event.get("Event", {})
                     .get("System", {})
                     .get("EventID", 0)
            )
        except (TypeError, ValueError):
            continue

        if eid not in KEY_EVENT_IDS:
            continue

        system     = event.get("Event", {}).get("System", {})
        event_data = event.get("Event", {}).get("EventData", {})
        payload    = json.dumps(event_data)

        susp, reason, technique, stage = _score_payload(payload)

        entry = {
            "event_id":    eid,
            "description": KEY_EVENT_IDS[eid],
            "time":        system.get("TimeCreated", {}).get("@SystemTime", ""),
            "computer":    system.get("Computer", ""),
            "payload_preview": payload[:400],
            "suspicious":  susp,
            "reason":      reason,
            "mitre_technique": technique,
            "kill_chain_stage": stage,
            "confidence":  "high" if susp else "low",
        }
        key_events.append(entry)
        if susp:
            suspicious.append(entry)
        if len(key_events) >= MAX_KEY_EVENTS:
            break

    return {
        "tool": "evtx_dump",
        "artifact": artifact,
        "total_key_events": len(key_events),
        "suspicious_count": len(suspicious),
        "key_events": key_events,
        "suspicious": suspicious,
        "error": None,
    }
