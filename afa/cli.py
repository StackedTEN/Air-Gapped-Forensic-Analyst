"""Command-line interface for the air-gapped forensic analyst."""

from __future__ import annotations

from pathlib import Path

import typer

from .brief import build_brief, render_brief
from .egress import EgressBlocked
from .loader import load_evidence
from .package import load_package, verify_package
from .providers import get_provider
from .report import render_attack_terminal, render_html, render_terminal
from .rootcause import build_reconstruction, render_rootcause
from .tools import map_attack, tool_names

app = typer.Typer(add_completion=False, help="An air-gapped, tool-grounded forensic analyst.")

# A standard line of investigative questions, used by the `report` command.
CASE_QUESTIONS = [
    "How did the attacker establish persistence on this host?",
    "What suspicious processes were executed?",
    "Was any external/removable storage device connected?",
    "Is there evidence of command-and-control network activity?",
    "Did the attacker take steps to cover their tracks?",
    "Build a timeline of the compromise.",
    "Map this incident to MITRE ATT&CK.",
]


@app.callback()
def main():
    """Air-gapped forensic analyst: a local LLM grounded in deterministic tools."""


def _build(mode: str, model: str | None):
    """Construct a provider, turning expected failures into clean messages."""
    try:
        return get_provider(mode, model)
    except EgressBlocked as exc:
        typer.secho(f"\n  air-gap guard: {exc}\n", fg=typer.colors.RED)
        raise typer.Exit(2)
    except RuntimeError as exc:
        typer.secho(f"\n  {exc}\n", fg=typer.colors.RED)
        raise typer.Exit(2)
    except Exception as exc:  # e.g. local model unreachable
        typer.secho(f"\n  could not start provider '{mode}': {exc}\n", fg=typer.colors.RED)
        raise typer.Exit(2)


def _evidence(evidence, events, registry, package=None, prefetch=None, shimcache=None,
              mft=None, browser=None, wmi=None):
    """Load evidence from a collection package, your own exports, or the bundled sample."""
    if package:
        ev, _ = load_package(package, verify=True)
        return ev
    return load_evidence(evidence, events_path=events, registry_path=registry,
                         prefetch_path=prefetch, shimcache_path=shimcache, mft_path=mft,
                         browser_path=browser, wmi_path=wmi)


# shared options
_EV = typer.Option(None, help="path to an evidence directory (bundled sample if omitted)")
_EVENTS = typer.Option(None, help="ingest your own events export (.json/.jsonl/.csv)")
_REG = typer.Option(None, help="ingest your own registry export (.json/.reg)")
_PKG = typer.Option(None, help="a collection package from the live collector (folder or .zip)")
_PF = typer.Option(None, help="ingest prefetch export (.json/.csv — e.g. PECmd)")
_SC = typer.Option(None, help="ingest shimcache/amcache export (.json/.csv)")
_MFT = typer.Option(None, help="ingest file-system timeline / $MFT export (.json/.csv — e.g. MFTECmd)")
_BR = typer.Option(None, help="ingest browser history export (.json/.csv — e.g. BrowsingHistoryView)")
_WMI = typer.Option(None, help="ingest WMI subscription export (.json/.csv)")
_MODE = typer.Option("offline", help="offline | local | cloud")
_MODEL = typer.Option(None, help="model name (local/cloud)")


@app.command()
def ask(
    question: str = typer.Argument(..., help="a natural-language investigative question"),
    mode: str = _MODE, model: str = _MODEL,
    evidence: Path = _EV, events: Path = _EVENTS, registry: Path = _REG, package: Path = _PKG,
    prefetch: Path = _PF, shimcache: Path = _SC, mft: Path = _MFT, browser: Path = _BR, wmi: Path = _WMI,
):
    """Ask one question about the evidence."""
    ev = _evidence(evidence, events, registry, package, prefetch, shimcache, mft, browser, wmi)
    render_terminal(_build(mode, model).investigate(question, ev))


@app.command()
def repl(mode: str = _MODE, model: str = _MODEL,
         evidence: Path = _EV, events: Path = _EVENTS, registry: Path = _REG, package: Path = _PKG,
         prefetch: Path = _PF, shimcache: Path = _SC, mft: Path = _MFT, browser: Path = _BR, wmi: Path = _WMI):
    """Interactive investigation prompt. Type 'exit' to quit."""
    ev = _evidence(evidence, events, registry, package, prefetch, shimcache, mft, browser, wmi)
    provider = _build(mode, model)
    typer.echo(f"  evidence: {ev.host}  ·  provider: {provider.name}  ·  type 'exit' to quit")
    while True:
        try:
            q = input("\nafa> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if q.lower() in ("exit", "quit", ""):
            break
        render_terminal(provider.investigate(q, ev))


@app.command()
def report(mode: str = _MODE, model: str = _MODEL,
           evidence: Path = _EV, events: Path = _EVENTS, registry: Path = _REG, package: Path = _PKG,
           prefetch: Path = _PF, shimcache: Path = _SC, mft: Path = _MFT, browser: Path = _BR, wmi: Path = _WMI,
           out: Path = typer.Option(Path("report.html"), help="HTML report output path")):
    """Run the standard case questions and write an HTML investigation report."""
    ev = _evidence(evidence, events, registry, package, prefetch, shimcache, mft, browser, wmi)
    provider = _build(mode, model)
    answers = [provider.investigate(q, ev) for q in CASE_QUESTIONS]
    recon = build_reconstruction(ev)
    out.write_text(render_html(answers, ev, map_attack(ev), recon=recon), encoding="utf-8")
    typer.echo(f"  wrote investigation report -> {out}")


@app.command()
def rootcause(evidence: Path = _EV, events: Path = _EVENTS, registry: Path = _REG, package: Path = _PKG,
              prefetch: Path = _PF, shimcache: Path = _SC, mft: Path = _MFT, browser: Path = _BR, wmi: Path = _WMI,
              out: Path = typer.Option(None, help="optional HTML report output path")):
    """Reconstruct the attack chain and determine the incident's root cause."""
    ev = _evidence(evidence, events, registry, package, prefetch, shimcache, mft, browser, wmi)
    recon = build_reconstruction(ev)
    typer.echo("\n" + render_rootcause(recon) + "\n")
    if out:
        out.write_text(render_html([], ev, map_attack(ev), recon=recon), encoding="utf-8")
        typer.echo(f"  wrote root-cause report -> {out}")


@app.command()
def case(packages: str = typer.Option(..., "--packages",
                                      help="a set of collection packages: a directory of packages, "
                                           "a single package, or a glob"),
         out: Path = typer.Option(None, help="optional self-contained campaign HTML report")):
    """Correlate a SET of packages into one cross-host campaign (v2).

    Verifies custody on every package (rejecting and naming any failure), then
    correlates across hosts: lateral-movement + shared-indicator graph, a unified
    host-tagged timeline, a campaign root cause, and an ATT&CK rollup. Fully local
    and deterministic — the evidence never leaves the host.
    """
    from .correlate import correlate_case, render_case_terminal
    campaign = correlate_case(packages)
    if not campaign["hosts"] and not campaign["rejected"]:
        typer.secho(f"\n  no collection packages found at: {packages}\n", fg=typer.colors.RED)
        raise typer.Exit(1)
    typer.echo("\n" + render_case_terminal(campaign) + "\n")
    if campaign["rejected"]:
        typer.secho(f"  {len(campaign['rejected'])} package(s) rejected for custody failure "
                    "(excluded from the campaign).", fg=typer.colors.RED)
    if out:
        from .report import render_case_html
        out.write_text(render_case_html(campaign), encoding="utf-8")
        typer.echo(f"  wrote campaign report -> {out}")


@app.command()
def attack(evidence: Path = _EV, events: Path = _EVENTS, registry: Path = _REG, package: Path = _PKG,
           prefetch: Path = _PF, shimcache: Path = _SC, mft: Path = _MFT, browser: Path = _BR, wmi: Path = _WMI,
           out: Path = typer.Option(None, help="optional HTML report output path")):
    """Map the evidence to MITRE ATT&CK techniques (deterministic, no model needed)."""
    ev = _evidence(evidence, events, registry, package, prefetch, shimcache, mft, browser, wmi)
    amap = map_attack(ev)
    render_attack_terminal(amap)
    if out:
        out.write_text(render_html([], ev, amap, render_brief(build_brief(ev))), encoding="utf-8")
        typer.echo(f"  wrote ATT&CK report -> {out}")


@app.command()
def brief(mode: str = _MODE, model: str = _MODEL,
          evidence: Path = _EV, events: Path = _EVENTS, registry: Path = _REG, package: Path = _PKG,
          prefetch: Path = _PF, shimcache: Path = _SC, mft: Path = _MFT, browser: Path = _BR, wmi: Path = _WMI):
    """Produce an executive incident brief grounded in the findings."""
    ev = _evidence(evidence, events, registry, package, prefetch, shimcache, mft, browser, wmi)
    provider = _build(mode, model)
    narrate = getattr(provider, "narrate", None)
    text = narrate(ev) if narrate else render_brief(build_brief(ev))
    typer.echo("\n" + text + "\n")


@app.command()
def verify(package: Path = typer.Argument(..., help="collection package (folder or .zip)")):
    """Verify a collection package's chain-of-custody and file integrity."""
    v = verify_package(package)
    m = v["manifest"]
    host = (m.get("host", {}) or {}).get("computer", "?")
    typer.echo(f"\n  case {m.get('case_id','?')}  ·  host {host}  ·  operator {m.get('operator','?')}")
    typer.echo(f"  collector v{m.get('collector_version','?')}  ·  profile {m.get('profile','?')}  ·  {m.get('collected_at','?')}\n")
    for f in v["files"]:
        mark = "OK " if f["ok"] else "BAD"
        typer.echo(f"  [{mark}] {f['name']}")
    if v["ok"]:
        typer.secho("\n  integrity verified — evidence is intact.\n", fg=typer.colors.GREEN)
    else:
        typer.secho("\n  INTEGRITY FAILURE — do not rely on this package.\n", fg=typer.colors.RED)
        raise typer.Exit(1)


@app.command()
def gui(evidence: Path = _EV, events: Path = _EVENTS, registry: Path = _REG, package: Path = _PKG,
        prefetch: Path = _PF, shimcache: Path = _SC, mft: Path = _MFT, browser: Path = _BR, wmi: Path = _WMI,
        mode: str = _MODE, model: str = _MODEL,
        port: int = typer.Option(8420, help="local port"),
        host: str = typer.Option("127.0.0.1", help="bind address (localhost only by default)")):
    """Launch the local web GUI (runs on 127.0.0.1, no egress)."""
    from .gui import serve
    src = {"dir": evidence, "events": events, "registry": registry, "package": package,
           "prefetch": prefetch, "shimcache": shimcache, "mft": mft, "browser": browser, "wmi": wmi,
           "mode": mode, "model": model}
    typer.echo(f"\n  Air-Gapped Forensic Analyst — http://{host}:{port}\n  (Ctrl+C to stop)\n")
    serve(src, host=host, port=port)


@app.command()
def tools():
    """List the forensic tools available to the agent."""
    for n in tool_names():
        typer.echo(f"  - {n}")


if __name__ == "__main__":
    app()
