"""Case-data read gateway — flat, audited reads of case artifacts that have no
live-tool equivalent (precooked Volatility/Plaso output, the Redline MANS DB,
the evidence manifest).

These let agent.py route ALL of its case-data OS reads through the MCP server
instead of touching the filesystem directly. They are deliberately thin: they
READ and return — all forensic reasoning stays in the agent. Every path is
scoped to the case root and opened read-only, so the gateway can never read
outside /cases or mutate evidence.
"""

import hashlib
import re
import sqlite3
from pathlib import Path

CASE_ROOT = Path("/cases")
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024   # absolute ceiling a caller may request
# Hard cap on bytes returned INLINE in a single response. The MCP stdio transport
# (and the agent's token budget) cannot carry a multi-MB payload — returning a
# whole 26 MB CSV inline closes the connection and takes the server down. Large
# artifacts must be paged via `offset` or grepped from the saved tool-result cache.
SAFE_INLINE_BYTES = 1 * 1024 * 1024     # 1 MiB
# Large/raw evidence is listed with size only (not hashed in full) for speed.
_HASH_SKIP_EXT = {".e01", ".001", ".img", ".raw", ".dd", ".mem", ".mans", ".zip",
                  ".pcap", ".pcapng", ".vmdk", ".vhd", ".vhdx"}


def _scoped(path: str):
    """Resolve path and confirm it sits under the case root. None if it escapes."""
    try:
        p = Path(path).resolve()
        p.relative_to(CASE_ROOT)
        return p
    except Exception:
        return None


def read_case_artifact(path: str, max_bytes: int = SAFE_INLINE_BYTES, offset: int = 0) -> dict:
    """Read a window of a (text) case artifact and return its content + SHA-256.

    For precooked tool output with no live equivalent (Volatility API-hooks
    dumps, Plaso supertimeline CSVs). Path is scoped to /cases and read-only.

    Only the requested window is read from disk (never the whole file), and the
    inline payload is hard-capped at SAFE_INLINE_BYTES so a large artifact can
    never overflow the stdio transport. For files larger than the cap, page with
    `offset` (use the returned `next_offset`) or grep the saved tool-result cache.

    Args:
        path: absolute path to the artifact, under /cases
        max_bytes: bytes to return this call (clamped to SAFE_INLINE_BYTES)
        offset: byte offset to start reading from (for paging large files)

    Returns:
        {tool, path, size_bytes, sha256, offset, returned_bytes, truncated,
         next_offset, content, error}
    """
    p = _scoped(path)
    if p is None:
        return {"error": f"path is outside the case root {CASE_ROOT}", "content": "", "path": path}
    if not p.is_file():
        return {"error": f"not a file: {path}", "content": "", "path": path}
    # clamp the window so a huge file can never overflow the stdio transport
    want = max(0, min(int(max_bytes), SAFE_INLINE_BYTES))
    off = max(0, int(offset))
    try:
        size = p.stat().st_size
        # stream-hash the full file for chain of custody (bounded memory)
        h = hashlib.sha256()
        with p.open("rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                h.update(block)
        # read only the requested window — never the whole file into memory
        with p.open("rb") as fh:
            if off:
                fh.seek(off)
            chunk = fh.read(want)
        end = off + len(chunk)
        return {
            "tool": "read_case_artifact",
            "path": str(p),
            "size_bytes": size,
            "sha256": h.hexdigest(),
            "offset": off,
            "returned_bytes": len(chunk),
            "truncated": end < size,
            "next_offset": end if end < size else None,
            "content": chunk.decode("utf-8", errors="replace"),
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "content": "", "path": str(p)}


def search_case_artifact(path: str, pattern: str, ignore_case: bool = True,
                         max_matches: int = 300, max_line: int = 400) -> dict:
    """Search a (text) case artifact server-side and return ONLY matching lines.

    Read-only, scoped to /cases. Streams the file line by line (bounded memory)
    and returns just the matched lines (capped) — so the agent searches case data
    THROUGH the MCP server instead of dumping it to a local file and grepping it.
    The MCP analogue of grep over precooked output (Plaso supertimeline CSVs, etc.).

    Args:
        path: absolute path to the artifact, under /cases
        pattern: a Python regular expression matched per line
        ignore_case: case-insensitive matching (default True)
        max_matches: cap on matching lines returned
        max_line: truncate each returned line to this many characters

    Returns:
        {tool, path, pattern, match_count, returned, truncated,
         matches: [{line, text}], error}
    """
    p = _scoped(path)
    if p is None:
        return {"error": f"path is outside the case root {CASE_ROOT}", "matches": [], "path": path}
    if not p.is_file():
        return {"error": f"not a file: {path}", "matches": [], "path": path}
    try:
        rx = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    except re.error as exc:
        return {"error": f"invalid regex: {exc}", "matches": [], "path": str(p)}
    matches = []
    count = 0
    try:
        with p.open("r", errors="replace") as fh:
            for i, line in enumerate(fh, 1):
                if rx.search(line):
                    count += 1
                    if len(matches) < max_matches:
                        matches.append({"line": i, "text": line.rstrip("\n")[:max_line]})
        return {
            "tool": "search_case_artifact",
            "path": str(p),
            "pattern": pattern,
            "match_count": count,
            "returned": len(matches),
            "truncated": count > len(matches),
            "matches": matches,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "matches": [], "path": str(p)}


def query_mans(mans_path: str, sql: str, params: list = None, limit: int = 5000) -> dict:
    """Run one read-only SELECT against a Redline Memoryze MANS SQLite database.

    The MANS DB has no live-tool equivalent, so the agent's queries execute here
    (file opened read-only, SELECT-only) and rows are returned. The query logic
    stays in the agent; this performs only the scoped, read-only DB access.

    Args:
        mans_path: absolute path to the .mans file, under /cases
        sql: a single SELECT statement (anything else is rejected)
        params: optional bound parameters
        limit: max rows returned

    Returns:
        {tool, path, columns, rows, rowcount, truncated, error}
    """
    p = _scoped(mans_path)
    if p is None:
        return {"error": f"path is outside the case root {CASE_ROOT}", "rows": []}
    if not p.is_file():
        return {"error": f"not a file: {mans_path}", "rows": []}
    s = (sql or "").strip().rstrip(";")
    if not s.lower().startswith("select"):
        return {"error": "only a single SELECT statement is permitted", "rows": []}
    if ";" in s:
        return {"error": "multiple statements are not permitted", "rows": []}
    try:
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        try:
            cur = con.execute(s, list(params or []))
            cols = [d[0] for d in cur.description] if cur.description else []
            rows = cur.fetchmany(limit + 1)
            truncated = len(rows) > limit
            return {
                "tool": "query_mans",
                "path": str(p),
                "columns": cols,
                "rows": [list(r) for r in rows[:limit]],
                "rowcount": min(len(rows), limit),
                "truncated": truncated,
                "error": None,
            }
        finally:
            con.close()
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "rows": []}


def build_evidence_manifest(case_dir: str) -> dict:
    """List + SHA-256 the evidence files under a case (chain-of-custody manifest).

    Large/raw images are listed with size only (not hashed in full) for speed.
    Replaces the agent's direct rglob+hashlib walk. Read-only, scoped to /cases.

    Args:
        case_dir: absolute path to the case directory, under /cases

    Returns:
        {tool, evidence_dir, files: {relpath: {sha256, size_bytes, hashed}},
         count, error}
    """
    p = _scoped(case_dir)
    if p is None:
        return {"error": f"path is outside the case root {CASE_ROOT}", "files": {}}
    ev = p / "evidence"
    if not ev.is_dir():
        return {"error": f"no evidence dir at {ev}", "files": {}}
    files: dict = {}
    try:
        for f in sorted(ev.rglob("*")):
            if not f.is_file():
                continue
            rel = str(f.relative_to(ev))
            size = f.stat().st_size
            if f.suffix.lower() in _HASH_SKIP_EXT:
                files[rel] = {"sha256": None, "size_bytes": size, "hashed": False}
            else:
                h = hashlib.sha256()
                with f.open("rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
                files[rel] = {"sha256": h.hexdigest(), "size_bytes": size, "hashed": True}
        return {
            "tool": "build_evidence_manifest",
            "evidence_dir": str(ev),
            "files": files,
            "count": len(files),
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "files": files}
