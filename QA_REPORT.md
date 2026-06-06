# QA Report — air-gapped-forensic-analyst

**Branch:** `qa-verify` (off `main`)
**Date:** 2026-06-05
**Scope:** verification + bug-fix hardening pass. No features added; product behavior preserved.
**Result:** ✅ fresh-venv install works · ✅ full suite green (**118 → 119**) · ✅ CLI end-to-end on both
sample sets with custody verified · ✅ GUI endpoints correct and 127.0.0.1-only · ✅ **zero egress in the
analyze path** · ✅ collector parses · 2 real bugs found and fixed.

---

## 1. Environment / install (Phase 1)

Fresh virtual environment, editable install + test/GUI deps:

```bash
python -m venv .venv-qa                       # Python 3.14.2, Windows 11
.venv-qa/Scripts/python.exe -m pip install -e . -r requirements-dev.txt
.venv-qa/Scripts/python.exe -c "import afa"   # OK
.venv-qa/Scripts/afa.exe --help               # entry point OK (exit 0)
```

Install succeeded with no packaging/dependency errors. The editable wheel built cleanly; the `afa`
console-script entry point resolves and runs. (Key resolved versions: fastapi 0.136.3, uvicorn 0.49.0,
typer 0.26.7, starlette 1.2.1, httpx 0.28.1, requests 2.34.2.)

## 2. Test suite (Phase 2)

```bash
.venv-qa/Scripts/python.exe -m pytest -q
```

| | count |
|---|---|
| Before (as found on `main`) | **118 passed**, 0 failed |
| After (this branch) | **119 passed**, 0 failed |

No pre-existing failures. The +1 is a new regression test (see Bug #1/#2). The only warning is an upstream
`StarletteDeprecationWarning` from FastAPI's `TestClient` ("install httpx2") — not a failure, not our code.
No test was weakened, skipped, or deleted.

## 3. End-to-end CLI (Phase 3)

Driven against the bundled synthetic samples only (no live collection). Every command exited **0** with
sane, non-empty output.

**Single host — `examples/sample-collection` (WEB-03):**

```bash
afa verify    examples/sample-collection      # integrity verified — all 12 files OK
afa rootcause --package examples/sample-collection   # root cause @ high confidence; kill-chain + IOCs
afa brief     --package examples/sample-collection   # Critical severity exec brief, grounded
afa attack    --package examples/sample-collection   # 22 techniques across 7 tactics
# five detectors via the grounded planner:
afa ask "Detect LOLBin abuse on this host"                 --package …   # 3 hits (certutil, rundll32)
afa ask "Decode any obfuscated commands and classify intent" --package … # 6 (1 base64-decoded)
afa ask "Find anomalous process lineage"                   --package …   # w3wp.exe -> cmd.exe (web shell)
afa ask "Was there timestomping?"                          --package …   # update.sys SI<FN ($MFT 0x10/0x30)
afa ask "Did the attacker cover their tracks?"             --package …   # VSS/USN/log-clear/Defender + blind spot
```

Each detector answer cites its deterministic tool as provenance and is tagged `air-gapped (no egress)`.

**Multi-host campaign — `examples/sample-case` (web-01 / db-02 / dc-01):**

```bash
afa verify examples/sample-case/web-01   # all three packages: integrity verified
afa verify examples/sample-case/db-02
afa verify examples/sample-case/dc-01
afa case --packages examples/sample-case --out campaign.html
```

Cross-host correlation output (exit 0): entry **WEB-01**, pivot chain `WEB-01 → DB-02 → DC-01` via Network
logons reusing `svc_backup`; three shared-indicator links (C2 `203.0.113.45`, a shared hash, the account);
ATT&CK rollup 13 techniques / 5 tactics; unified 12-event timeline. Self-contained campaign HTML written.

## 4. GUI (Phase 4)

In-process Starlette/FastAPI `TestClient` assertions (all passed):

- `GET /` → 200, serves the SPA (`<!doctype html>`, `RENDER`, `detections`).
- `GET /api/case` → 200, full payload; `artifacts` contains all five detector arrays —
  `lolbins` (3), `command_intent` (6), `lineage` (1), `antiforensics` (4), `timestomp` (1) — plus
  `rootcause`, `attack`, `custody`, `manifest`, `counts`.
- `POST /api/ask` → 200, `grounded: true` with tool_calls.

Real-bind smoke test: `afa gui --port 8477` → `netstat` shows `TCP 127.0.0.1:8477 LISTENING` only —
**never `0.0.0.0`**; server responded on loopback and was shut down cleanly (port freed).

`node --check` on the JS embedded in `afa/static/index.html`: **SYNTAX OK** (≈17.6 KB extracted).

## 5. Invariants & egress audit (Phase 5)

Audited every import/use of `requests`/`urllib`/`httpx`/`socket` and every `http(s)://`/CDN/asset
reference across `afa/`:

- **Offline analyze path makes zero network calls.** `requests` is only ever *lazily* imported inside the
  `local` (Ollama, localhost, guarded by `assert_local`) and `cloud` (opt-in, refused unless
  `AFA_ALLOW_EGRESS=1`) providers. Proven empirically: with `socket.connect`/`create_connection`/
  `urlopen` monkeypatched to raise, the full offline pipeline (load+verify package → rootcause → brief →
  ATT&CK → render per-host HTML → cross-host correlate → render campaign HTML) completes successfully and
  all offline answers remain grounded.
- **Custody model intact.** Collector SHA-256 hashes → analyzer recomputes and compares; all four sample
  packages verify; tampering still fails (existing tests cover this, all green).
- **Simulated data stays labeled.** All IOCs are RFC-5737 / `.test` / `.example` documentation ranges;
  reports carry the `air-gapped · no egress` badge (flips to `egress used` only in cloud mode).
- The SPA (`afa/static/index.html`) and the campaign report (`render_case_html`) were already fully
  self-contained.

→ One real egress leak found and fixed: **Bug #1** below.

## 6. Static checks (Phase 6)

- `ruff check afa tests --select F,E9` (pyflakes + syntax): initially 11 findings — **no** undefined names
  and **no** syntax errors, i.e. no broken code; all were unused imports (10) + one dead local variable.
  Fixed; ruff now reports **All checks passed**.
- `py_compile` across `afa/`, `tests/`, `examples/`: all OK.
- PowerShell collector `collector/Invoke-AfaCollect.ps1`: parsed with the PowerShell language parser
  (`[Parser]::ParseFile`) — **0 errors, 3799 tokens** (PSScriptAnalyzer not installed; parser used as the
  documented fallback). No live collection executed.

---

## Bugs found & fixed

### Bug #1 — per-host HTML report fetched fonts from a remote CDN (breaks the air-gap)
**Severity:** high (violates the core zero-egress promise on a generated artifact).
`afa/report.py`'s `render_html()` emitted `<link rel="preconnect">` + a Google Fonts `<link
href="https://fonts.googleapis.com/...">` stylesheet. Opening a generated investigation report
(`afa report/rootcause/attack --out …`) on an analyst workstation would reach out to
`fonts.googleapis.com` / `fonts.gstatic.com` — exactly the off-host network call the tool exists to
prevent. (The campaign report `render_case_html()` was already clean; only the per-host renderer leaked.)
**Fix:** dropped the three remote `<link>` tags and added offline font fallbacks
(`"Spline Sans",system-ui,sans-serif` · `"Fraunces",Georgia,serif` · `"JetBrains Mono",ui-monospace,
monospace`) — the same self-contained pattern `render_case_html` already used. Verified: a regenerated
report has **0** `googleapis`/`gstatic`/`<link>`/`@import`/`url(http` references; the 5 remaining `http://`
strings are IOC evidence text (RFC-5737 ranges), not asset fetches.

### Bug #2 — per-host report written with the platform default encoding (mojibake on Windows)
**Severity:** medium (corrupts output cross-platform; surfaced by the Bug #1 regression test).
`afa/cli.py`'s `report`, `rootcause`, and `attack` commands wrote the HTML via `out.write_text(html)` with
**no `encoding=`**. On Windows that defaults to cp1252, so the em-dash in `Investigation — <host>` and the
`·` separators were written as cp1252 bytes while the document declares `<meta charset="utf-8">` — a
byte/charset mismatch that renders as mojibake (and raises `UnicodeDecodeError` when the file is read back
as UTF-8). The `case` command already did this correctly (`encoding="utf-8"`).
**Fix:** added `encoding="utf-8"` to all three `out.write_text(...)` calls, matching `case`. Verified: the
regenerated report reads back as valid UTF-8 with the em-dash and `·` intact.

### Cleanups (no behavior change)
- Removed unused imports flagged by ruff: `afa/brief.py` (`search_events`), `afa/providers.py`
  (`egress_allowed`), `afa/report.py` (`json`), `afa/rootcause.py` (`_is_external`,
  `_suspicious_proc_names`, `detect_lineage_anomalies`, `prefetch_execution`), and three in
  `tests/test_afa.py` (`os`, `extract_iocs`, `render_case_terminal`).
- Removed a dead local variable `sources` in `afa/correlate._campaign_rootcause` (assigned, never read).

### New regression test (added, nothing weakened)
`tests/test_afa.py::TestCaseCli::test_report_cli_writes_self_contained_per_host_html` runs the real
`afa report` CLI and asserts the per-host HTML has no external asset references and reads back as UTF-8.
This test fails on the pre-fix code (it caught **both** bugs above) and passes after the fix — closing the
coverage gap (the suite previously guarded only the SPA and the campaign report for self-containment).

---

## Residual risks / things to verify manually
- **Live collection not exercised.** Per instructions, the PowerShell collector was only parse-checked,
  not run. A real `Invoke-AfaCollect.ps1` triage on a Windows host should be validated separately —
  including the documented PS 5.1 UTF-8-BOM behavior (the Python loaders already read `utf-8-sig`, so BOM
  packages load; confirm the collector itself writes what you expect end-to-end).
- **`local`/`cloud` provider paths** require Ollama / an API key and were not run live; their egress
  guards are unit-tested and were not modified.
- **Upstream deprecation:** FastAPI's `TestClient` emits a `StarletteDeprecationWarning` (httpx). Harmless
  today; worth tracking for a future dependency bump.
- **Cosmetic observation (not a bug, not changed):** in `rootcause`, the "Defense evasion" chain step can
  show a 2009 timestamp — that is the genuine timestomped `$STANDARD_INFORMATION` date from the evidence
  (`update.sys`), i.e. grounded data, not a fabrication. Left as-is to avoid altering product behavior.
