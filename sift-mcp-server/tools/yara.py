"""YARA pattern matching — hunt_yara MCP tool function.

Runs YARA rules against a target path (file, directory, or memory image).
Returns structured match list with rule name, file, and offset.

Based in part on marez8505/find-evil yara.py (MIT licence).
"""

import re
from pathlib import Path
from parsers.common import run_tool, save_raw_output, tool_missing_response

MAX_MATCHES = 200


def hunt_yara(rules_path: str, target_path: str, output_dir: str) -> dict:
    """Run YARA rules against a file, directory, or memory image.

    Args:
        rules_path: Path to a .yar/.yara rules file or directory of rules
        target_path: File or directory to scan
        output_dir: Write directory for raw output (audit trail)

    Returns:
        {
            tool, rules_path, target_path, match_count,
            matches: [ {rule, tags, meta, file, offset, matched_strings} ],
            error
        }
    """
    if not Path(rules_path).exists():
        return {"error": f"rules_path does not exist: {rules_path}",
                "matches": [], "match_count": 0}

    if not Path(target_path).exists():
        return {"error": f"target_path does not exist: {target_path}",
                "matches": [], "match_count": 0}

    # -r: recursive if directory  -s: print matching strings
    cmd = ["yara", "-r", "-s", rules_path, target_path]
    r = run_tool(cmd, timeout=300)

    if r["tool_missing"]:
        return tool_missing_response(
            "YARA",
            "Install: sudo apt-get install -y yara  "
            "or build from source: https://github.com/VirusTotal/yara",
        )

    save_raw_output(output_dir, "yara_matches.txt", r["stdout"])

    matches = _parse_yara_output(r["stdout"])

    return {
        "tool": "yara",
        "rules_path": rules_path,
        "target_path": target_path,
        "match_count": len(matches),
        "matches": matches[:MAX_MATCHES],
        "error": r["stderr"][:500] if r["returncode"] != 0 else None,
    }


def _parse_yara_output(stdout: str) -> list[dict]:
    """Parse YARA text output into structured match list.

    YARA output format:
        RuleName [tag1,tag2] /path/to/file
        0x1234:$string_name: matched bytes...
    """
    matches: list[dict] = []
    current: dict = {}

    # Regex for the rule + file line
    rule_re  = re.compile(r"^(\S+)\s+(?:\[([^\]]*)\]\s+)?(.+)$")
    # Regex for the matched string offset line
    match_re = re.compile(r"^(0x[0-9a-fA-F]+):\$(\S+):\s*(.*)$")

    for line in stdout.splitlines():
        line = line.rstrip()
        if not line:
            continue

        m = match_re.match(line)
        if m and current:
            current.setdefault("matched_strings", []).append({
                "offset": m.group(1),
                "name":   f"${m.group(2)}",
                "bytes":  m.group(3)[:80],
            })
            continue

        m2 = rule_re.match(line)
        if m2:
            if current:
                matches.append(current)
            rule_name = m2.group(1)
            tags      = [t.strip() for t in (m2.group(2) or "").split(",") if t.strip()]
            file_path = m2.group(3).strip()
            current = {
                "rule":            rule_name,
                "tags":            tags,
                "file":            file_path,
                "matched_strings": [],
                "mitre_technique": _technique_from_rule(rule_name),
                "kill_chain_stage": "execution",
                "confidence":      "high",
            }

    if current:
        matches.append(current)

    return matches


def _technique_from_rule(rule_name: str) -> str:
    """Best-effort MITRE technique from rule name conventions."""
    name = rule_name.lower()
    if any(x in name for x in ("webshell", "web_shell")):
        return "T1505.003"
    if "ransomware" in name:
        return "T1486"
    if any(x in name for x in ("rat", "remote_access", "c2")):
        return "T1071"
    if "inject" in name:
        return "T1055"
    if "mimikatz" in name or "credential" in name:
        return "T1003"
    if "persistence" in name or "startup" in name:
        return "T1547"
    return "T1588"   # generic: Obtain Capabilities
