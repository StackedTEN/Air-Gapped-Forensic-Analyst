# CLAUDE.md

Guidance for working in this repo. Read the `README.md` for the product pitch; this file is the engineering contract.

## The core rule (non-negotiable)

**Every analytical claim must trace to a deterministic tool. No ungrounded assertions.**

This is the whole point of the project, not a style preference. The model orchestrates; the evidence decides. Concretely:

- The forensic facts come from the deterministic tool belt in `afa/tools.py` (plain functions over parsed evidence). The model — when one is used at all — only chooses which tools to call and composes prose from what they return. It never reads raw bytes and guesses.
- Every answer must be backed by at least one tool result, surfaced as provenance. A test (`tests/test_afa.py`) asserts that a full offline investigation is grounded — each answer built from ≥1 tool call. Don't break that invariant.
- ATT&CK techniques and root-cause conclusions are produced by **rules that return their supporting evidence** (`ATTACK_RULES` in `afa/tools.py`; correlation logic in `afa/rootcause.py`). A technique with no evidence row must not appear.
- When you can't write a deterministic resolver for a question, that's the signal it's an analyst judgment call — surface it as a stated gap (see `rootcause`'s "what's missing" section), do **not** let the model assert it.
- Stay calibrated, not confident: root cause carries an explicit confidence and an honest list of missing telemetry. Naming an unsupported root cause is the exact failure this project exists to prevent.

If you add a feature that makes the model assert something a tool can't confirm, you've regressed the product even if every test passes.

## Architecture

Pipeline: **COLLECT → PACKAGE → ANALYZE**.

```
collector/Invoke-AfaCollect.ps1   read-only live triage collector (Windows, PowerShell)
                                  → writes a collection package (artifacts + manifest)

afa/package.py    load a collection package + verify chain-of-custody (SHA-256) before analysis
afa/loader.py     Evidence dataclass; load bundled/own evidence into the schema the tools expect
afa/normalize.py  ingest real exports (Get-WinEvent JSON, CSV, .reg) into that schema
afa/tools.py      the deterministic forensic tool belt — the oracle the agent must use; ATTACK_RULES
afa/rootcause.py  attack-chain reconstruction + root-cause determination + IOC extraction
afa/brief.py      grounded executive incident brief (deterministic, or model-written from tool facts)
afa/providers.py  offline planner · local Ollama agent loop · gated cloud provider
afa/egress.py     the air-gap guard (loopback allowed; remote refused unless AFA_ALLOW_EGRESS=1)
afa/report.py     terminal output + standalone HTML investigation report
afa/gui.py        local FastAPI web console (binds 127.0.0.1, no egress) + static/index.html SPA
afa/cli.py        Typer CLI entrypoint (see commands below)

artifacts/                 synthetic Windows evidence (registry.json + events.jsonl); all IPs are RFC 5737
examples/sample-collection/ a worked live-triaged package (host WEB-03), Python-generated
tests/test_afa.py          the suite
```

### Data flow

A **collection package** = normalized artifact JSON files (`events.json`, `registry.json`,
`processes.json`, `network.json`, `users.json`, `services.json`, `programs.json`) plus a
`manifest.json` carrying chain-of-custody (case id, operator, host, collector version, time)
and a SHA-256 per file. `afa/package.py` recomputes every hash and **refuses to analyze a
package whose hashes don't match the manifest** — verify is a gate, not a formality.

### The three modes (`afa/providers.py`)

| Mode | Driver | Egress |
| --- | --- | --- |
| `offline` (default) | deterministic intent router over the tools | none |
| `local` | local model via Ollama on loopback | none |
| `cloud` | remote API | **refused unless `AFA_ALLOW_EGRESS=1`** |

The air-gap is structural, not documentation: `afa/egress.py`'s `assert_local()` raises
`EgressBlocked` on any remote URL unless egress is explicitly enabled. Don't weaken this guard.

### CLI commands (`afa/cli.py`)

`ask` · `repl` · `report` · `attack` · `brief` · `rootcause` · `verify` · `gui` · `tools`.
Most analysis commands accept `--package <dir|zip>`, or `--evidence` / `--events` / `--registry`
to point at your own exports. `gui` binds `127.0.0.1:8420` by default.

```bash
python -m afa.cli verify    examples/sample-collection
python -m afa.cli rootcause --package examples/sample-collection
python -m afa.cli gui       --package examples/sample-collection   # http://127.0.0.1:8420
```

## Tests

Setup and run (Windows / PowerShell shown; adapt the activate path on other OSes):

```bash
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
```

Run the suite:

```bash
pytest -q
```

Current status: **47 tests pass**. The suite proves the tools find the real persistence/USB/C2/
scheduled-task/account/anti-forensic artifacts (and stay quiet on absent ones); that every mapped
ATT&CK technique is evidence-backed; that ingest normalizes Get-WinEvent JSON, CSV, and `.reg`;
that a package loads and that tampering with any file fails the custody check and blocks analysis;
that root-cause reconstructs the kill-chain in order, extracts the right IOCs, and holds the
correct confidence (dropping to low when nothing malicious is present); that the agent loop chains
tools and assembles a grounded answer under a scripted model; that the egress guard blocks remote
URLs by default; and that every offline answer is grounded in ≥1 tool call.

If you change anything, `pytest -q` must stay green. If you add a tool, an ATT&CK rule, or a
normalizer, add the test that proves it finds the real artifact **and** stays quiet on its absence.

## Conventions & gotchas

- **Python ≥ 3.10** (`pyproject.toml`). Validated locally on 3.14.
- The collector is **strictly read-only** and does **live triage, not disk imaging**. Keep it that way: it must only read OS-native facilities and write solely to its output folder.
- **Encoding boundary (known issue):** the loader reads JSON with `read_text()` (no `utf-8-sig`),
  so a UTF-8 **BOM** breaks parsing (`JSONDecodeError: Expecting value: line 1 column 1 (char 0)`).
  Windows PowerShell 5.1's `Out-File -Encoding utf8` writes a BOM — so packages produced by the
  live collector on PS 5.1 currently fail to load even though their SHA-256 hashes are valid. The
  bundled `examples/sample-collection` avoids this only because it's Python-generated. Fix
  deliberately (read `utf-8-sig` in `afa/package.py` + `afa/normalize.py`, and/or write BOM-less
  UTF-8 from the collector) — do not paper over it.
- Synthetic artifacts only; all addresses are RFC 5737 documentation ranges. Don't introduce real IOCs.
- No build step, no external/CDN assets in the GUI — it must run on an isolated host with zero egress.
