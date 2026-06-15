# Accuracy & Evidence-Integrity Report

A self-assessment of findings accuracy, false positives, missed artifacts, hallucination
risk, and the evidence-integrity / spoliation model. Written to be honest rather than
flattering — calibrated doubt is a feature of this agent, and this report holds it to the
same standard.

---

## 1. How accuracy is enforced (not just measured)

Three mechanisms run *before* a finding is allowed to exist:

- **Artifact + offset requirement.** Every finding must cite a concrete `artifact` and
  `offset`. A claim with no traceable source cannot be committed.
- **Independent judge gate.** A separate agent re-opens each finding's cited artifact
  *through the MCP server* and returns `confirmed` / `flagged`. The gateway
  `/commit-findings` endpoint rejects any finding without a judge verdict. The judge is not
  the same context that produced the finding.
- **TTP cross-check.** The judge validates each ATT&CK technique against
  `reference/ttp_reference.json`; a mismatch is flagged with the suggested technique.

## 2. False positives (and how they were caught)

- **`cnn.exe` — caught and self-corrected.** On the Vanko case the agent initially proposed
  that a `cnn.exe` present only in Prefetch (binary absent from the collection) was a
  *deleted-after-execution implant* (anti-forensic). On pulling the Prefetch path hint it
  read `\Program Files\WindowsApps\588E6FFA.CNNAppForWindows...\CNN.EXE` — the legitimate
  CNN Store app, which CyLR simply hadn't collected. The agent **retracted the finding
  before the judge ran.** This is the single most important data point in this report: the
  system surfaced a plausible-but-wrong claim and killed it.
- **SRL-2015 "memory-resident only" — flagged.** An over-claim that an implant was
  memory-resident was contradicted by an on-disk copy; the judge flagged it and it was
  corrected.

No false positive survived into a committed `findings_log.json` in these runs.

## 3. Missed artifacts & coverage gaps (disclosed, not hidden)

The Vanko `coverage_report.json` deliberately shows what the evidence *could* support but
that no tool reached:

- **BitLocker-locked disk** (`surface_physical.E01`) — 0 files; no recovery key. The disk's
  contents (including the actual `vacation photos.7z` payload) were **not** examined.
- **Amcache.hve** — dirty hive; the parser produced no CSV (needs transaction-log replay).
  Amcache execution evidence was therefore not used.
- **Standalone `$MFT`** — not parseable by `fls` in isolation (needs MFTECmd).
- **Weakest committed finding** — the USB-exfil finding (T1052.001) is *corroborative*: the
  Apple/Dropbox-autoplay configuration predates the theft by ~12 days, so it supports rather
  than directly proves removable-media exfil. It is committed at `medium` confidence and the
  judge noted exactly this.

Unknowns that remain open: the exact contents/size of `vacation photos.7z`, and whether the
Dropbox upload completed — both require the locked disk and cloud logs.

## 4. Hallucination posture

- The agent grounds conclusions in raw tool output and is instructed never to fabricate
  artifacts, contents, or system state.
- The artifact+offset rule plus the independent judge make an unsupported claim
  *uncommittable*, not merely discouraged.
- Coverage reporting names the tools that **failed or were not run**, so absent analysis is
  visible rather than silently implied as "clean."

## 5. Evidence integrity & spoliation resistance

Integrity is enforced architecturally, and was exercised during real engagements:

- **Read-only evidence.** `/cases/<case>/evidence` is write/edit-denied three ways: the
  harness permission deny-list, the exec gateway's case-path deny in forensic mode, and
  filesystem permissions. Evidence was never modified.
- **MCP-only evidence access.** Case data is reachable only through typed MCP functions.
  Attempts during the engagement to read case data via raw shell were **denied by the
  gateway** — observed, not theoretical.
- **Denied dangerous operations.** In forensic mode, `curl`, `wget`, `rm`, `bash`, and
  arbitrary interpreters are rejected before execution; only one vetted interpreter
  (`guardrails.py`) may run. These denials are logged in the gateway audit trail.
- **Spoliation test.** Switching to "dev" mode (needed for tooling) is a deliberate, logged
  flip of `.gateway_mode`; case work always runs in forensic. We verified that forensic mode
  blocks the bypass paths (raw evidence reads, network egress, deletion) rather than relying
  on the model to refrain.
- **Sanctioned writes only.** Findings/theory/coverage are written exclusively through the
  gateway commit endpoints, which enforce the judge gate — the agent cannot hand-write a
  `findings_log.json` into a case directory.

## 6. Quantitative results

| Dataset | Intent | IOC coverage | MITRE TTPs | Findings |
|---------|--------|--------------|-----------|----------|
| VIGIA-REAL-002 | MALICE ✓ (= GT) | 5/5 (100%) | 3/5 (**F1 0.60**) | 6, all judge-confirmed |
| Vanko | MALICE | n/a (scenario) | 8 techniques across 4 tactics | 8/8 judge-confirmed |
| SRL-2015 | MALICE | n/a | T1055/T1547.001/T1071.001/T1036.005 | persistence/injection; 1 self-correction |

The VIGIA F1 of 0.60 is reported as-is. Both misses were **labeling** divergences from the
NIST answer key (equivalent concealment tagged with a different ID; an exfil channel
under-tagged), not detection misses — the activity itself was fully characterized and all
five key IOCs were referenced. That finding drove the TTP reference + judge cross-check now
in the pipeline.

## 7. Known limitations

Adversarial anti-forensic evasion (MITRE ATLAS) and encrypted/locked media remain the
hardest cases — the agent reports these as blockers rather than guessing past them.
