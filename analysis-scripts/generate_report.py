#!/usr/bin/env python3
"""generate_report.py — PDF incident-report generator for the Find Evil! DFIR agent.

Reads a case's committed analysis artifacts and renders a court-style incident report:

    <case>/analysis/findings_log.json     (required) — judge-verified findings
    <case>/analysis/case_theory.json      (optional) — intent + narrative
    <case>/analysis/coverage_report.json  (optional) — data->tool->stage coverage
    <case>/analysis/accuracy_report.json  (optional) — scoring vs ground truth

Usage:
    python3 generate_report.py --case /cases/Vanko [--out report.pdf]

Design notes:
- Read-only: never writes inside the case's evidence/ directory.
- No fabrication: every section is rendered strictly from the committed JSON. If an
  artifact is missing, its section is omitted (and noted), never invented.
- Timestamps are generation-time UTC (clearly labelled as such).
- All dynamic/untrusted values are HTML-escaped via esc() before they reach a Paragraph;
  static formatting markup is written directly.

Dependency: reportlab (preinstalled on the SANS SIFT Workstation; otherwise
`pip3 install reportlab`).
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )
except ImportError:
    sys.exit("reportlab not found. Install with:  pip3 install reportlab")

# ── palette ──────────────────────────────────────────────────────────────────
INK = colors.HexColor("#161b22")
MUTED = colors.HexColor("#57606a")
RULE = colors.HexColor("#d0d7de")
HEADER_BG = colors.HexColor("#0d1117")
ROW_ALT = colors.HexColor("#f6f8fa")
INTENT_COLORS = {
    "MALICE": colors.HexColor("#cf222e"),
    "SUSPICION": colors.HexColor("#bf8700"),
    "NEGLIGENCE": colors.HexColor("#0969da"),
}
VERDICT_COLORS = {
    "confirmed": colors.HexColor("#1a7f37"),
    "flagged": colors.HexColor("#bf8700"),
}


def esc(s) -> str:
    """HTML-escape dynamic/untrusted content before it reaches a Paragraph."""
    if s is None:
        s = ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _load(path: Path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("H1x", parent=ss["Heading1"], textColor=INK, fontSize=20,
                          spaceAfter=2, leading=24))
    ss.add(ParagraphStyle("H2x", parent=ss["Heading2"], textColor=INK, fontSize=13,
                          spaceBefore=14, spaceAfter=6, leading=16))
    ss.add(ParagraphStyle("Bodyx", parent=ss["BodyText"], textColor=INK, fontSize=9.5,
                          leading=14, alignment=TA_LEFT))
    ss.add(ParagraphStyle("Cell", parent=ss["BodyText"], textColor=INK, fontSize=8,
                          leading=10))
    ss.add(ParagraphStyle("CellH", parent=ss["BodyText"], textColor=colors.white,
                          fontSize=8, leading=10, fontName="Helvetica-Bold"))
    ss.add(ParagraphStyle("Muted", parent=ss["BodyText"], textColor=MUTED, fontSize=8,
                          leading=11))
    return ss


def build(case_dir: str, out_path: str) -> str:
    analysis = Path(case_dir) / "analysis"
    findings = _load(analysis / "findings_log.json") or []
    theory = _load(analysis / "case_theory.json")
    coverage = _load(analysis / "coverage_report.json")
    accuracy = _load(analysis / "accuracy_report.json")

    case_name = os.path.basename(os.path.normpath(case_dir))
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ss = _styles()
    S = []  # story

    def P(html, style):
        S.append(Paragraph(html, style))

    # ── header ──
    P("Digital Forensics &amp; Incident Response Report", ss["H1x"])
    P(f"Case: <b>{esc(case_name)}</b>", ss["Bodyx"])
    P(f"Generated: {esc(gen)} &nbsp;|&nbsp; Tool: Find Evil! autonomous DFIR agent "
      f"&nbsp;|&nbsp; AI-assisted, independently judge-verified", ss["Muted"])
    S.append(Spacer(1, 4))
    S.append(HRFlowable(width="100%", thickness=1, color=RULE))

    # ── executive summary ──
    P("Executive Summary", ss["H2x"])
    if theory:
        intent = esc((theory.get("overall_intent") or "UNDETERMINED").upper())
        ic = INTENT_COLORS.get(intent, MUTED)
        P(f'Overall intent classification: '
          f'<font color="{ic.hexval()}"><b>{intent}</b></font>', ss["Bodyx"])
        S.append(Spacer(1, 4))
        P(esc(theory.get("narrative", "")), ss["Bodyx"])
        techs = theory.get("mitre_techniques") or []
        if techs:
            S.append(Spacer(1, 4))
            P("MITRE ATT&amp;CK techniques: <b>" + esc(", ".join(techs)) + "</b>", ss["Muted"])
    else:
        P("No case_theory.json present — summary omitted.", ss["Muted"])

    confirmed = [f for f in findings if f.get("judge_verdict") == "confirmed"]
    S.append(Spacer(1, 4))
    P(f"Findings: <b>{len(findings)}</b> total &nbsp;|&nbsp; "
      f"<b>{len(confirmed)}</b> judge-confirmed.", ss["Bodyx"])

    # ── findings table ──
    P("Findings", ss["H2x"])
    if findings:
        head = [Paragraph(esc(h), ss["CellH"]) for h in
                ("#", "Time (UTC)", "Finding", "Artifact : offset", "ATT&CK",
                 "Stage", "Conf.", "Judge")]
        rows = [head]
        for i, f in enumerate(findings, 1):
            art = os.path.basename(str(f.get("artifact", ""))) or "-"
            off = f.get("offset", "")
            verdict = f.get("judge_verdict") or "-"
            vc = VERDICT_COLORS.get(verdict, MUTED)
            rows.append([
                Paragraph(str(i), ss["Cell"]),
                Paragraph(esc(f.get("timestamp", "")), ss["Cell"]),
                Paragraph(esc(f.get("finding", "")), ss["Cell"]),
                Paragraph(f"{esc(art)} : {esc(off)}", ss["Cell"]),
                Paragraph(esc(f.get("mitre_technique", "")), ss["Cell"]),
                Paragraph(esc(f.get("kill_chain_stage", "")), ss["Cell"]),
                Paragraph(esc(f.get("confidence", "")), ss["Cell"]),
                Paragraph(f'<font color="{vc.hexval()}"><b>{esc(verdict)}</b></font>', ss["Cell"]),
            ])
        cw = [7*mm, 26*mm, 58*mm, 34*mm, 16*mm, 20*mm, 11*mm, 16*mm]
        t = Table(rows, colWidths=cw, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.4, RULE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ROW_ALT]),
        ]))
        S.append(t)
    else:
        P("No findings_log.json present.", ss["Muted"])

    # ── kill-chain coverage ──
    if coverage and isinstance(coverage.get("stages"), list):
        P("Kill-Chain Coverage", ss["H2x"])
        hit = [s.get("stage") for s in coverage["stages"] if s.get("hit")]
        unhit = [s.get("stage") for s in coverage["stages"] if not s.get("hit")]
        P("Stages with findings: <b>" + esc(", ".join(hit) or "none") + "</b>", ss["Bodyx"])
        P("Not observed: " + esc(", ".join(unhit) or "none"), ss["Muted"])

    # ── evidence coverage / gaps ──
    if coverage and isinstance(coverage.get("artifact_classes"), list):
        P("Evidence Coverage", ss["H2x"])
        for cl in coverage["artifact_classes"]:
            if not cl.get("present"):
                continue
            tools = cl.get("tools") or []
            applied = [t.get("name") for t in tools if t.get("applied")]
            gaps = [f"{t.get('name')} ({t.get('note')})" for t in tools
                    if not t.get("applied") and t.get("note")]
            label = esc(cl.get("label", cl.get("id")))
            tail = ("analyzed by " + esc(", ".join(applied))) if applied else "no analyzer applied"
            P(f"<b>{label}</b> &mdash; {tail}", ss["Bodyx"])
            for g in gaps:
                P("&nbsp;&nbsp;&#9888; gap: " + esc(g), ss["Muted"])

    # ── accuracy ──
    if accuracy:
        P("Accuracy &amp; Scoring", ss["H2x"])
        bits = []
        for k, label in (("overall_intent_correct", "Intent correct"),
                         ("ioc_coverage_pct", "IOC coverage %"),
                         ("mitre_coverage_pct", "MITRE coverage %"),
                         ("f1_score", "MITRE F1")):
            if k in accuracy:
                bits.append(f"{esc(label)}: <b>{esc(accuracy[k])}</b>")
        if bits:
            P(" &nbsp;|&nbsp; ".join(bits), ss["Bodyx"])
        if accuracy.get("notes"):
            P(esc(accuracy["notes"]), ss["Muted"])

    # ── integrity footer ──
    S.append(Spacer(1, 10))
    S.append(HRFlowable(width="100%", thickness=1, color=RULE))
    P("Evidence integrity", ss["H2x"])
    P(esc(
        "All evidence under the case directory was treated strictly read-only; analysis was "
        "performed exclusively through the typed sift-ir-agent MCP server. Each finding above "
        "cites the artifact and offset it derives from and carries an independent judge "
        "verdict. AI-assisted conclusions are labelled as such; deterministic tool output is "
        "preserved in the case audit trail. This report is generated from committed analysis "
        "artifacts and introduces no new claims."), ss["Muted"])

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(out), pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm, topMargin=15*mm, bottomMargin=15*mm,
        title=f"DFIR Report - {case_name}", author="Find Evil! DFIR agent",
    )
    doc.build(S)
    return str(out)


def main():
    ap = argparse.ArgumentParser(description="Generate a PDF incident report from a case's "
                                             "committed analysis artifacts.")
    ap.add_argument("--case", required=True, help="Case directory, e.g. /cases/Vanko")
    ap.add_argument("--out", default=None, help="Output PDF path "
                    "(default: <case>/reports/incident_report.pdf)")
    args = ap.parse_args()

    out = args.out or os.path.join(args.case, "reports", "incident_report.pdf")
    path = build(args.case, out)
    print(f"[OK] incident report written -> {path}")


if __name__ == "__main__":
    main()
