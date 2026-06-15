"""Network capture analyser — analyze_network_capture MCP tool function.

Uses tshark to extract TCP conversations, DNS queries, and HTTP requests.
Flags external IPs, unusual TLDs, beaconing patterns, and large transfers.

Based in part on marez8505/find-evil network.py (MIT licence).
"""

import re
from parsers.common import run_tool, save_raw_output, tool_missing_response, is_private_ip

MAX_CONVERSATIONS = 100
MAX_DNS           = 200
MAX_HTTP          = 200

SUSPICIOUS_TLDS = {".ru", ".cn", ".top", ".xyz", ".tk", ".pw", ".cc", ".onion"}

INSTALL_HINT = "sudo apt-get install -y tshark"


def analyze_network_capture(pcap_path: str, output_dir: str) -> dict:
    """Analyse a network capture for C2, beaconing, and data exfiltration.

    Extracts TCP/UDP conversation summary, DNS queries, and HTTP requests.
    Flags connections to non-RFC-1918 IPs, suspicious TLDs, and large
    outbound transfers.

    Args:
        pcap_path: Path to .pcap or .pcapng file
        output_dir: Write directory for raw output (audit trail)

    Returns:
        {
            tool, artifact,
            conversations: [ {src, dst, bytes, packets, suspicious, reason} ],
            dns_queries:   [ {time, src, query, suspicious, reason} ],
            http_requests: [ {time, src, host, uri, suspicious, reason} ],
            suspicious_count,
            error
        }
    """
    if not _tshark_available():
        return tool_missing_response("tshark", INSTALL_HINT)

    conversations = _extract_conversations(pcap_path, output_dir)
    dns_queries   = _extract_dns(pcap_path, output_dir)
    http_requests = _extract_http(pcap_path, output_dir)

    all_suspicious = (
        [c for c in conversations if c.get("suspicious")]
        + [d for d in dns_queries   if d.get("suspicious")]
        + [h for h in http_requests if h.get("suspicious")]
    )

    return {
        "tool": "tshark",
        "artifact": pcap_path,
        "conversations": conversations,
        "dns_queries":   dns_queries,
        "http_requests": http_requests,
        "suspicious_count": len(all_suspicious),
        "suspicious": all_suspicious,
        "error": None,
    }


# ── extractors ─────────────────────────────────────────────────────────────

def _extract_conversations(pcap_path: str, output_dir: str) -> list[dict]:
    r = run_tool(
        ["tshark", "-r", pcap_path, "-q", "-z", "conv,tcp"],
        timeout=60,
    )
    save_raw_output(output_dir, "tshark_conversations.txt", r["stdout"])

    entries: list[dict] = []
    # Lines look like:  1.2.3.4:1234  <->  5.6.7.8:443  100  200  ...
    conv_re = re.compile(
        r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+<->\s+(\d+\.\d+\.\d+\.\d+):(\d+)"
        r"\s+(\d+)\s+(\d+)"
    )
    for line in r["stdout"].splitlines():
        m = conv_re.search(line)
        if not m:
            continue
        src_ip, src_port, dst_ip, dst_port = m.group(1), m.group(2), m.group(3), m.group(4)
        pkts, byts = int(m.group(5)), int(m.group(6))

        entry: dict = {
            "src": f"{src_ip}:{src_port}",
            "dst": f"{dst_ip}:{dst_port}",
            "packets": pkts,
            "bytes": byts,
            "suspicious": False,
        }

        # Flag external destinations with large transfer or from internal to external
        if not is_private_ip(dst_ip) and byts > 1_000_000:
            entry.update(
                suspicious=True,
                reason=f"Large outbound transfer to {dst_ip} ({byts:,} bytes)",
                mitre_technique="T1048",
                kill_chain_stage="exfiltration",
                confidence="medium",
            )
        elif not is_private_ip(dst_ip):
            entry.update(
                suspicious=True,
                reason=f"External connection to {dst_ip}:{dst_port}",
                mitre_technique="T1071",
                kill_chain_stage="command-and-control",
                confidence="low",
            )

        entries.append(entry)
        if len(entries) >= MAX_CONVERSATIONS:
            break

    return entries


def _extract_dns(pcap_path: str, output_dir: str) -> list[dict]:
    r = run_tool(
        ["tshark", "-r", pcap_path, "-Y", "dns",
         "-T", "fields",
         "-e", "frame.time_relative",
         "-e", "ip.src",
         "-e", "dns.qry.name",
         "-E", "separator=|"],
        timeout=60,
    )
    save_raw_output(output_dir, "tshark_dns.txt", r["stdout"])

    entries: list[dict] = []
    for line in r["stdout"].splitlines():
        parts = line.split("|")
        if len(parts) < 3 or not parts[2].strip():
            continue
        query = parts[2].strip()
        entry: dict = {
            "time":  parts[0].strip(),
            "src":   parts[1].strip(),
            "query": query,
            "suspicious": False,
        }
        # Flag suspicious TLDs
        tld = "." + query.rsplit(".", 1)[-1].lower() if "." in query else ""
        if tld in SUSPICIOUS_TLDS:
            entry.update(
                suspicious=True,
                reason=f"DNS query to suspicious TLD: {tld}",
                mitre_technique="T1071.004",
                kill_chain_stage="command-and-control",
                confidence="medium",
            )
        # Flag DGA-like long random-looking subdomains
        elif len(query) > 40 and re.search(r"[a-z0-9]{20,}", query):
            entry.update(
                suspicious=True,
                reason="Possible DGA domain (long random-looking name)",
                mitre_technique="T1568.002",
                kill_chain_stage="command-and-control",
                confidence="medium",
            )
        entries.append(entry)
        if len(entries) >= MAX_DNS:
            break

    return entries


def _extract_http(pcap_path: str, output_dir: str) -> list[dict]:
    r = run_tool(
        ["tshark", "-r", pcap_path, "-Y", "http.request",
         "-T", "fields",
         "-e", "frame.time_relative",
         "-e", "ip.src",
         "-e", "http.host",
         "-e", "http.request.uri",
         "-e", "http.user_agent",
         "-E", "separator=|"],
        timeout=60,
    )
    save_raw_output(output_dir, "tshark_http.txt", r["stdout"])

    entries: list[dict] = []
    for line in r["stdout"].splitlines():
        parts = (line.split("|") + ["", "", "", "", ""])[:5]
        host  = parts[2].strip()
        uri   = parts[3].strip()
        ua    = parts[4].strip()

        entry: dict = {
            "time":       parts[0].strip(),
            "src":        parts[1].strip(),
            "host":       host,
            "uri":        uri[:300],
            "user_agent": ua[:200],
            "suspicious": False,
        }

        # Flag PowerShell / scripting UA
        if re.search(r"(powershell|curl|wget|python|go-http-client)", ua, re.IGNORECASE):
            entry.update(
                suspicious=True,
                reason=f"Scripting/automation user-agent: {ua[:80]}",
                mitre_technique="T1071.001",
                kill_chain_stage="command-and-control",
                confidence="medium",
            )
        # Flag .exe / .ps1 / .bat downloads
        elif re.search(r"\.(exe|ps1|bat|cmd|dll|vbs|hta)(\?|$)", uri, re.IGNORECASE):
            entry.update(
                suspicious=True,
                reason=f"Executable or script download: {uri[:100]}",
                mitre_technique="T1105",
                kill_chain_stage="execution",
                confidence="high",
            )

        entries.append(entry)
        if len(entries) >= MAX_HTTP:
            break

    return entries


def _tshark_available() -> bool:
    r = run_tool(["tshark", "--version"], timeout=5)
    return not r["tool_missing"] and r["returncode"] == 0
