# Dataset Documentation

This agent was developed and evaluated against three datasets of increasing realism. All
are forensic training/reference images with documented ground truth; **no production or
personally-identifying data was used**, and evidence was treated strictly read-only
throughout (see [ACCURACY.md](ACCURACY.md) for the integrity model).

> Evidence files themselves are **not** committed to this repository (chain of custody;
> see `.gitignore`). This document describes the sources and how to reproduce the analysis.

---

## 1. Vanko — insider data theft (primary showcase)

**Scenario.** A Windows host (`StarkSurface`, user `anthony.vanko` / "PC User") suspected
of exfiltrating classified research.

**Evidence acquired.**
- `surface_physical.E01` — physical disk image (**BitLocker-encrypted**; no recovery key
  available, so filesystem analysis returned 0 files — recorded as a blocker, not hidden).
- `vanko-c-drive.CYLR` — a CyLR live-response collection: `$MFT`, Prefetch, Windows event
  logs, Amcache, and per-user registry hives (`NTUSER.DAT`, `UsrClass.dat`).

**What the agent found (8 findings, all independently judge-confirmed).** A complete
insider-exfiltration chain on 29–30 June 2016:

| Stage | Technique | Evidence |
|-------|-----------|----------|
| Initial access | T1078 | Mapped `\\192.168.1.5\StarkResearch` as drive Z: (NTUSER `Network`/`MountPoints2`) |
| Collection | T1039 | Browsed `Level 7/8 Classified` / `Biochemical` / `Mutant Genome`; opened classified `.docx` (BagMRU + Word MRU) |
| Collection | T1560.001 | 7-Zip `ArcHistory` → `vacation photos.7z` + `NinaResearch.zip` |
| Collection | T1074.001 | Staged on removable D: under a decoy `vacation photos` tree (TypedPaths) |
| Defense evasion | T1564 | Innocuous "vacation photos" naming concealing classified content |
| Defense evasion | T1070.004 | SDelete (secure-wipe) `EulaAccepted`; VeraCrypt run x6 |
| Exfiltration | T1567.002 | Dropbox web session + `ks2` keystore rewrite + desktop client |
| Exfiltration | T1052.001 | Removable D: + Apple USB device wired to a Dropbox autoplay handler |

The agent **excluded the examiner's own acquisition activity** (FTK Imager,
MagnetRAMCapture, `VankoLogical.E01`, StarkCollector — 2017–2018) from the suspect timeline,
and corrected an early false lead (`cnn.exe`; see ACCURACY.md).

**Reproducibility.**
1. Place the evidence under `/cases/Vanko/evidence/`.
2. `build_evidence_manifest(/cases/Vanko)` to inventory.
3. `build_supertimeline(evidence_dir=".../Windows/Prefetch", output_dir=...)` and again on
   `.../Users/PC User/NTUSER.DAT` (separate output dirs).
4. `search_case_artifact` the resulting `timeline.csv` for `StarkResearch`, `7-Zip`,
   `vacation photos`, `SDelete`, `dropbox`, `MountPoints2`.
5. Draft findings → independent judge pass → `guardrails.py commit --kind findings`.

Outputs land in `/cases/Vanko/analysis/` (`findings_log.json`, `case_theory.json`,
`coverage_report.json`).

---

## 2. SRL-2015 — Zeus banking trojan (Windows XP)

**Scenario.** A Windows XP host (`xp-tdungan`) infected with Zeus.

**What the agent found.** Process-injection and persistence artifacts via the memory and
registry tools, mapped to T1055 / T1547.001 / T1071.001 / T1036.005. This case produced a
second self-correction: an over-claimed "memory-resident only" finding was contradicted by
an on-disk implant and was corrected/flagged.

**Note.** Volatility 3 could not parse this XP image; the agent reported the limitation
rather than fabricating a memory analysis.

---

## 3. VIGIA-REAL-002 — NIST data-leakage (scored)

**Scenario.** An insider data-leakage case scored against a published `ground_truth.json`
(verdict + 5 MITRE TTPs + 5 key IOCs).

**Result (honestly reported, not retro-edited).**
- Intent: **MALICE = ground truth** ✓
- IOC coverage: **5/5 (100%)** ✓
- MITRE TTPs: **3/5 (F1 0.60)** — two *labeling* divergences (file-extension concealment
  tagged T1036.008 vs the key's T1564; the email-exfil channel under-tagged T1048), not
  detection failures.

This scoring directly produced `reference/ttp_reference.json` and the judge's TTP
cross-check, which closes that labeling gap on subsequent runs.

---

## Summary

| Dataset | Type | Ground truth | Headline result |
|---------|------|--------------|-----------------|
| Vanko | Insider exfil (disk + CyLR) | Scenario key | 8/8 judge-confirmed; full chain |
| SRL-2015 | Zeus (memory/registry, WinXP) | Scenario key | Persistence/injection; 1 self-correction |
| VIGIA-REAL-002 | NIST data-leakage | `ground_truth.json` | Intent ✓, IOC 5/5, TTP F1 0.60 |
