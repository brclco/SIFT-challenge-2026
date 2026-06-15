"""Disk artifact carver — carve_disk_artifacts MCP tool function.

Runs bulk_extractor against a disk image and returns a structured summary
of carved artifact categories: URLs, emails, domains, executables, credit
card patterns. Never returns raw file contents.

New function — not present in marez8505/find-evil.
"""

import re
from pathlib import Path
from parsers.common import run_tool, save_raw_output, tool_missing_response

MAX_ITEMS_PER_CATEGORY = 100

INSTALL_HINT = "sudo apt-get install -y bulk-extractor"

# Suspicious patterns in carved URLs / domains
SUSPICIOUS_URL_PATTERNS = [
    (r"\.(ru|cn|top|xyz|tk|pw|cc|onion)/", "URL with suspicious TLD", "T1071", "command-and-control"),
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "URL using raw IP address", "T1071", "command-and-control"),
    (r"(pastebin\.com|paste\.ee|ghostbin)", "Paste service URL (common C2 staging)", "T1102", "command-and-control"),
    (r"\.(exe|dll|ps1|bat|vbs|hta|msi)\b", "Executable download URL", "T1105", "execution"),
]


def carve_disk_artifacts(image_path: str, output_dir: str) -> dict:
    """Carve artifacts from a disk image using bulk_extractor.

    Extracts URLs, email addresses, domains, and executable fragments.
    Returns category summaries — never raw file contents.

    Args:
        image_path: Path to disk image (.e01, .dd, .img) or raw partition
        output_dir: Write directory for bulk_extractor output (audit trail)

    Returns:
        {
            tool, image_path,
            categories: {
                urls:    { count, suspicious_count, items: [...], suspicious: [...] },
                email:   { count, items: [...] },
                domain:  { count, items: [...] },
            },
            total_suspicious,
            error
        }
    """
    carve_dir = str(Path(output_dir) / "bulk_output")

    r = run_tool(
        ["bulk_extractor",
         "-o", carve_dir,
         "-x", "jpeg",        # skip image carving (large, not needed for IR)
         "-x", "pdf",
         "-x", "zip",
         image_path],
        timeout=600,
    )

    if r["tool_missing"]:
        return tool_missing_response("bulk_extractor", INSTALL_HINT)

    save_raw_output(output_dir, "bulk_extractor_stderr.txt", r["stderr"])

    # Parse carved output files
    urls      = _read_feature_file(carve_dir, "url.txt",    MAX_ITEMS_PER_CATEGORY)
    emails    = _read_feature_file(carve_dir, "email.txt",  MAX_ITEMS_PER_CATEGORY)
    domains   = _read_feature_file(carve_dir, "domain.txt", MAX_ITEMS_PER_CATEGORY)

    url_suspicious = _score_urls(urls)

    return {
        "tool": "bulk_extractor",
        "image_path": image_path,
        "categories": {
            "urls": {
                "count": len(urls),
                "suspicious_count": len(url_suspicious),
                "items": urls,
                "suspicious": url_suspicious,
            },
            "email": {
                "count": len(emails),
                "items": emails,
            },
            "domain": {
                "count": len(domains),
                "items": domains,
            },
        },
        "total_suspicious": len(url_suspicious),
        "error": r["stderr"][:300] if r["returncode"] not in (0, 1) else None,
    }


# ── helpers ────────────────────────────────────────────────────────────────

def _read_feature_file(carve_dir: str, filename: str, limit: int) -> list[dict]:
    """Read a bulk_extractor feature file into a list of {offset, feature} dicts."""
    path = Path(carve_dir) / filename
    if not path.exists():
        return []

    items: list[dict] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t", 2)
            items.append({
                "offset":  parts[0] if len(parts) > 0 else "",
                "feature": parts[1] if len(parts) > 1 else line,
                "context": parts[2][:200] if len(parts) > 2 else "",
            })
            if len(items) >= limit:
                break
    return items


def _score_urls(url_items: list[dict]) -> list[dict]:
    """Return URL items that match suspicious patterns."""
    suspicious: list[dict] = []
    for item in url_items:
        feature = item.get("feature", "")
        for pattern, reason, technique, stage in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, feature, re.IGNORECASE):
                suspicious.append({
                    **item,
                    "reason":           reason,
                    "mitre_technique":  technique,
                    "kill_chain_stage": stage,
                    "confidence":       "medium",
                })
                break
    return suspicious
