"""Render an investigation: terminal output and a standalone HTML report."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .loader import Evidence
from .models import Answer


def render_terminal(ans: Answer) -> None:
    try:
        from rich.console import Console
        from rich.panel import Panel
    except ImportError:
        _plain(ans)
        return
    c = Console()
    c.print()
    c.print(Panel(ans.text, title=f"[bold]{ans.question}[/]",
                  border_style="yellow", title_align="left"))
    if ans.tool_calls:
        c.print("  [dim]provenance — every fact above came from these tool calls:[/]")
        for t in ans.tool_calls:
            args = ", ".join(f"{k}={v}" for k, v in t.args.items()) or "—"
            c.print(f"   [cyan]{t.name}[/]({args}) -> {t.summary}")
    else:
        c.print("  [red]ungrounded answer — no tools were called[/]")
    egress = "[red]egress used[/]" if ans.egress_used else "[green]air-gapped (no egress)[/]"
    c.print(f"  provider: {ans.provider}   {egress}\n")


def _plain(ans: Answer) -> None:
    print(f"\nQ: {ans.question}\nA: {ans.text}\n")
    for t in ans.tool_calls:
        args = ", ".join(f"{k}={v}" for k, v in t.args.items()) or "—"
        print(f"   {t.name}({args}) -> {t.summary}")
    print(f"   provider: {ans.provider}  egress: {ans.egress_used}\n")


def render_attack_terminal(attack_map: dict) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box
    except ImportError:
        print(f"\nATT&CK: {attack_map['technique_count']} techniques / "
              f"{attack_map['tactics_covered']} tactics")
        for t in attack_map["techniques"]:
            print(f"  {t['id']:<12} {t['name']}  [{'/'.join(t['tactics'])}]  ({t['count']} evidence)")
        print()
        return
    c = Console()
    c.print(f"\n  [bold]MITRE ATT&CK[/]  {attack_map['technique_count']} techniques · "
            f"{attack_map['tactics_covered']} tactics\n")
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Technique", style="cyan", width=12)
    table.add_column("Name")
    table.add_column("Tactics", style="yellow")
    table.add_column("Evidence", width=8)
    for t in attack_map["techniques"]:
        table.add_row(t["id"], t["name"], " / ".join(t["tactics"]), str(t["count"]))
    c.print(table)
    c.print()


def render_html(answers: list[Answer], ev: Evidence, attack_map: dict | None = None,
                brief_text: str | None = None, recon: dict | None = None) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    provider = answers[0].provider if answers else "offline-planner"
    egress = any(a.egress_used for a in answers)
    blocks = []
    for a in answers:
        prov = "".join(
            f"""<div class="tc"><span class="tn">{html.escape(t.name)}</span>"""
            f"""<span class="ta">{html.escape(', '.join(f'{k}={v}' for k, v in t.args.items()) or '—')}</span>"""
            f"""<span class="tr">{html.escape(t.summary)}</span></div>"""
            for t in a.tool_calls
        )
        grounded = "grounded" if a.grounded else "ungrounded"
        blocks.append(f"""
      <section class="qa">
        <div class="q">{html.escape(a.question)}</div>
        <div class="a">{html.escape(a.text)}</div>
        <div class="prov-label">provenance · {len(a.tool_calls)} tool call(s) · <span class="{grounded}">{grounded}</span></div>
        <div class="prov">{prov or '<span class="ungrounded">no tools called</span>'}</div>
      </section>""")

    brief_html = ""
    if brief_text:
        brief_html = (
            '<section class="brief-wrap"><h2>Executive summary</h2>'
            '<span class="brief-tag">auto-generated from the findings below</span>'
            f'<pre class="brief">{html.escape(brief_text)}</pre></section>'
        )

    rootcause_html = ""
    if recon and recon.get("chain"):
        steps = "".join(
            f'<div class="step"><div class="step-dot">{i}</div>'
            f'<div class="step-body"><div class="step-head">{html.escape(s["title"])}'
            f'<span class="step-ts">{html.escape(s["ts"])}</span></div>'
            f'<div class="chips">{"".join(f"<span class=chip>{html.escape(t)}</span>" for t in s["techniques"])}</div>'
            f'</div></div>'
            for i, s in enumerate(recon["chain"], 1)
        )
        io = recon["iocs"]
        ioc_rows = ""
        for label, vals in (("C2", io["c2"]), ("Hashes", io["file_hashes"]),
                            ("Files", io["suspicious_paths"]), ("Accounts", io["accounts"])):
            if vals:
                ioc_rows += (f'<div class="ioc-row"><span class="ioc-k">{label}</span>'
                             f'<span class="ioc-v">{html.escape(", ".join(vals))}</span></div>')
        gaps = "".join(f"<li>{html.escape(g)}</li>" for g in recon["gaps"])
        pivots = "".join(f"<li>{html.escape(p)}</li>" for p in recon["pivots"])
        rootcause_html = (
            '<section class="rc-wrap">'
            '<div class="rc-callout"><span class="rc-label">Root cause</span>'
            f'<span class="rc-conf rc-{recon["root_cause_confidence"]}">{recon["root_cause_confidence"]} confidence</span>'
            f'<p class="rc-text">{html.escape(recon["root_cause"])}</p></div>'
            f'<h3 class="rc-h">Attack chain</h3><div class="chain">{steps}</div>'
            f'<div class="rc-cols"><div class="rc-col"><h4>Indicators to pivot on</h4>'
            f'<div class="iocs">{ioc_rows}</div></div>'
            f'<div class="rc-col"><h4>What\'s missing &amp; next steps</h4>'
            f'<ul class="rc-list">{gaps}{pivots}</ul></div></div></section>'
        )

    matrix_html = ""
    if attack_map and attack_map["techniques"]:
        cols = []
        for tactic in attack_map["tactics"]:
            cells = "".join(
                f'<div class="cell"><span class="tid">{html.escape(t["id"])}</span>'
                f'<span class="tname">{html.escape(t["name"].split(":")[-1].strip())}</span>'
                f'<span class="cnt">{t["count"]}&times;</span></div>'
                for t in attack_map["techniques"] if tactic in t["tactics"]
            )
            cols.append(f'<div class="tcol"><h4>{html.escape(tactic)}</h4>{cells}</div>')
        matrix_html = (
            '<section class="attack-wrap"><div class="attack-head">'
            '<h2>MITRE ATT&amp;CK</h2>'
            f'<span class="attack-meta">{attack_map["technique_count"]} techniques · '
            f'{attack_map["tactics_covered"]} tactics — every cell traceable to evidence</span></div>'
            f'<div class="matrix">{"".join(cols)}</div></section>'
        )

    egress_badge = (
        '<span class="badge warn">egress used</span>' if egress
        else '<span class="badge ok">air-gapped · no egress</span>'
    )

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Investigation — {html.escape(ev.host)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,500;9..144,600&family=Spline+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
  :root {{ --ink:#15110d; --ink2:#1d1712; --line:#382e25; --paper:#efe6d8; --muted:#9b8f7e;
    --faint:#6f6453; --ember:#e0603a; --gold:#e0a838; --teal:#46c08e; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:radial-gradient(900px 500px at 82% -10%, rgba(70,192,142,.08), transparent 60%), var(--ink);
    color:var(--paper); font-family:"Spline Sans",sans-serif; line-height:1.55; -webkit-font-smoothing:antialiased; }}
  .wrap {{ max-width:920px; margin:0 auto; padding:46px 24px 80px; }}
  .kicker {{ font-family:"JetBrains Mono",monospace; font-size:12px; letter-spacing:.22em;
    text-transform:uppercase; color:var(--ember); margin:0 0 10px; }}
  h1 {{ font-family:"Fraunces",serif; font-weight:600; font-size:clamp(28px,5vw,44px);
    line-height:1.04; margin:0 0 8px; letter-spacing:-.01em; }}
  .sub {{ color:var(--muted); max-width:62ch; margin:0 0 22px; }}
  .meta {{ display:flex; gap:10px; flex-wrap:wrap; margin-bottom:36px; }}
  .badge {{ font-family:"JetBrains Mono",monospace; font-size:11px; letter-spacing:.06em;
    padding:6px 12px; border-radius:999px; border:1px solid var(--line); color:var(--muted); }}
  .badge.ok {{ color:var(--teal); border-color:rgba(70,192,142,.4); background:rgba(70,192,142,.07); }}
  .badge.warn {{ color:var(--ember); border-color:rgba(224,96,58,.4); background:rgba(224,96,58,.07); }}
  .qa {{ border:1px solid var(--line); border-radius:14px; padding:22px 24px; margin-bottom:16px;
    background:linear-gradient(180deg,var(--ink2),transparent); }}
  .q {{ font-family:"Fraunces",serif; font-size:19px; font-weight:500; margin-bottom:12px; }}
  .a {{ color:#ded2c0; margin-bottom:16px; }}
  .prov-label {{ font-family:"JetBrains Mono",monospace; font-size:10px; letter-spacing:.12em;
    text-transform:uppercase; color:var(--faint); margin-bottom:10px; }}
  .grounded {{ color:var(--teal); }} .ungrounded {{ color:var(--ember); }}
  .prov {{ display:flex; flex-direction:column; gap:6px; }}
  .tc {{ display:grid; grid-template-columns:160px 1fr auto; gap:12px; align-items:baseline;
    font-family:"JetBrains Mono",monospace; font-size:12px; padding:8px 12px; background:var(--ink);
    border:1px solid var(--line); border-left:3px solid var(--gold); border-radius:8px; }}
  .tn {{ color:var(--gold); }} .ta {{ color:var(--muted); word-break:break-word; }}
  .tr {{ color:var(--teal); white-space:nowrap; }}
  @media (max-width:640px) {{ .tc {{ grid-template-columns:1fr; }} .tr {{ white-space:normal; }} }}
  .rc-wrap {{ margin-bottom:30px; }}
  .rc-callout {{ border:1px solid rgba(224,96,58,.35); background:rgba(224,96,58,.08);
    border-radius:14px; padding:18px 22px; margin-bottom:22px; }}
  .rc-label {{ font-family:"JetBrains Mono",monospace; font-size:11px; letter-spacing:.14em;
    text-transform:uppercase; color:var(--ember); font-weight:700; }}
  .rc-conf {{ float:right; font-family:"JetBrains Mono",monospace; font-size:10px; padding:2px 9px;
    border-radius:20px; text-transform:uppercase; letter-spacing:.06em; }}
  .rc-high {{ background:rgba(220,80,60,.25); color:#f2b8a8; }}
  .rc-medium {{ background:rgba(214,167,75,.22); color:#e6cf9a; }}
  .rc-low {{ background:rgba(140,140,140,.2); color:#cfcfcf; }}
  .rc-text {{ font-family:"Fraunces",serif; font-size:19px; line-height:1.45; margin:10px 0 0; color:#f0e6d6; }}
  .rc-h {{ font-family:"JetBrains Mono",monospace; font-size:11px; letter-spacing:.1em; text-transform:uppercase;
    color:var(--muted); margin:0 0 14px; }}
  .chain {{ margin-bottom:24px; }}
  .step {{ display:flex; gap:14px; align-items:flex-start; padding-bottom:14px; position:relative; }}
  .step:not(:last-child)::before {{ content:""; position:absolute; left:13px; top:28px; bottom:0;
    width:2px; background:var(--line); }}
  .step-dot {{ flex:0 0 28px; height:28px; border-radius:50%; background:var(--ember); color:#1a120c;
    font-family:"JetBrains Mono",monospace; font-weight:700; font-size:13px; display:flex;
    align-items:center; justify-content:center; z-index:1; }}
  .step-head {{ font-family:"Fraunces",serif; font-size:17px; color:#ede1cf; }}
  .step-ts {{ font-family:"JetBrains Mono",monospace; font-size:11px; color:var(--faint); margin-left:10px; }}
  .chips {{ margin-top:6px; }}
  .chip {{ display:inline-block; font-family:"JetBrains Mono",monospace; font-size:10.5px;
    color:var(--ember); border:1px solid rgba(224,96,58,.3); border-radius:6px; padding:2px 7px; margin:3px 5px 0 0; }}
  .rc-cols {{ display:flex; flex-wrap:wrap; gap:22px; }}
  .rc-col {{ flex:1 1 300px; }}
  .rc-col h4 {{ font-family:"JetBrains Mono",monospace; font-size:11px; letter-spacing:.08em;
    text-transform:uppercase; color:var(--muted); margin:0 0 10px; }}
  .ioc-row {{ display:flex; gap:10px; padding:6px 0; border-bottom:1px solid var(--line); font-size:12.5px; }}
  .ioc-k {{ flex:0 0 70px; color:var(--ember); font-family:"JetBrains Mono",monospace; font-size:11px; }}
  .ioc-v {{ color:#d8ccba; word-break:break-word; }}
  .rc-list {{ margin:0; padding-left:18px; color:#cdc1b0; font-size:12.5px; line-height:1.6; }}
  .brief-wrap {{ border:1px solid var(--line); border-left:3px solid var(--ember); border-radius:14px;
    padding:20px 24px; margin-bottom:30px; background:linear-gradient(180deg,var(--ink2),transparent); }}
  .brief-wrap h2 {{ font-family:"Fraunces",serif; font-weight:500; font-size:22px; margin:0 0 4px; }}
  .brief-tag {{ font-family:"JetBrains Mono",monospace; font-size:10px; letter-spacing:.1em;
    text-transform:uppercase; color:var(--faint); }}
  pre.brief {{ font-family:"JetBrains Mono",monospace; font-size:12.5px; line-height:1.6; color:#ded2c0;
    white-space:pre-wrap; word-break:break-word; margin:12px 0 0; }}
  .attack-wrap {{ margin-bottom:32px; }}
  .attack-head {{ display:flex; align-items:baseline; gap:14px; flex-wrap:wrap; margin-bottom:14px; }}
  .attack-head h2 {{ font-family:"Fraunces",serif; font-weight:500; font-size:22px; margin:0; }}
  .attack-meta {{ font-family:"JetBrains Mono",monospace; font-size:11px; color:var(--faint); }}
  .matrix {{ display:flex; flex-wrap:wrap; gap:10px; }}
  .tcol {{ flex:1 1 140px; min-width:140px; }}
  .tcol h4 {{ font-family:"JetBrains Mono",monospace; font-size:10px; letter-spacing:.08em;
    text-transform:uppercase; color:var(--muted); margin:0 0 8px; padding-bottom:8px;
    border-bottom:1px solid var(--line); }}
  .cell {{ background:rgba(224,96,58,.08); border:1px solid rgba(224,96,58,.28); border-radius:8px;
    padding:9px 11px; margin-bottom:8px; }}
  .cell .tid {{ display:block; font-family:"JetBrains Mono",monospace; font-size:12px; font-weight:600;
    color:var(--ember); }}
  .cell .tname {{ display:block; font-size:11px; color:#d8ccba; margin-top:3px; line-height:1.3; }}
  .cell .cnt {{ font-family:"JetBrains Mono",monospace; font-size:10px; color:var(--faint); }}
  footer {{ margin-top:44px; color:var(--faint); font-size:12px; font-family:"JetBrains Mono",monospace; }}
</style></head>
<body><div class="wrap">
  <p class="kicker">Judgment in the loop · local LLM</p>
  <h1>Investigation — {html.escape(ev.host)}</h1>
  <p class="sub">An AI analyst answered each question by calling deterministic forensic tools.
  Every claim is traceable to a tool result below — the model orchestrates, the evidence decides.</p>
  <div class="meta">
    {egress_badge}
    <span class="badge">provider · {html.escape(provider)}</span>
    <span class="badge">{len(ev.events)} events · {len(ev.registry)} registry rows</span>
  </div>
  {rootcause_html}
  {brief_html}
  {matrix_html}
  {''.join(blocks)}
  <footer>generated {now} &nbsp;·&nbsp; air-gapped-forensic-analyst</footer>
</div></body></html>"""


# ==========================================================================
# Campaign (cross-host) report — fully self-contained, no external requests.
# Reuses the ink+ember theme; fonts are referenced by name and degrade to system
# fallbacks (no font-CDN <link>), so the file works on a zero-egress host.
# ==========================================================================
def _case_graph_svg(campaign: dict) -> str:
    """Hand-rolled, dependency-free SVG of the host graph.

    Hosts are nodes laid out in pivot order; directed lateral-movement edges arc
    above with timestamped arrows; undirected shared-indicator edges arc below,
    dashed and differently coloured.
    """
    hosts = campaign["hosts"]
    if not hosts:
        return ""
    # order: entry first, then directed-edge destinations, then the rest
    order: list[str] = []
    if campaign.get("entry_host"):
        order.append(campaign["entry_host"])
    for e in campaign["directed_edges"]:
        for h in (e["source"], e["dest"]):
            if h not in order:
                order.append(h)
    for h in hosts:
        if h["host"] not in order:
            order.append(h["host"])
    by_name = {h["host"]: h for h in hosts}
    order = [h for h in order if h in by_name]

    n = len(order)
    W, H, NY = 900, 340, 170
    left, right = 110, 110
    span = (W - left - right)
    xs = {h: (left + (span * i / (n - 1) if n > 1 else span / 2)) for i, h in enumerate(order)}

    def esc(s):  # local escape helper
        return html.escape(str(s))

    parts = [
        f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="host correlation graph" class="cgraph">',
        '<defs><marker id="arrow" markerWidth="11" markerHeight="11" refX="9" refY="5" '
        'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="var(--ember)"/></marker></defs>',
    ]

    # undirected edges (below the row, dashed)
    for k, e in enumerate(campaign["undirected_edges"]):
        a, b = e["hosts"]
        if a not in xs or b not in xs:
            continue
        xa, xb = xs[a], xs[b]
        cy = NY + 70 + (k % 3) * 16
        mx = (xa + xb) / 2
        kinds = ", ".join(sorted({s["type"] for s in e["shared"]}))
        parts.append(f'<path d="M{xa:.0f},{NY+24} Q{mx:.0f},{cy:.0f} {xb:.0f},{NY+24}" '
                     f'fill="none" stroke="var(--gold)" stroke-width="1.4" '
                     f'stroke-dasharray="5 4" opacity="0.8"/>')
        parts.append(f'<text x="{mx:.0f}" y="{cy+12:.0f}" class="elabel shared">{esc(kinds)}</text>')

    # directed edges (above the row, solid, arrowhead + timestamp)
    for k, e in enumerate(campaign["directed_edges"]):
        a, b = e["source"], e["dest"]
        if a not in xs or b not in xs:
            continue
        xa, xb = xs[a], xs[b]
        cy = NY - 80 - (k % 2) * 26
        mx = (xa + xb) / 2
        # start/end slightly inset so the arrow meets the node edge
        sx = xa + (10 if xb > xa else -10)
        ex = xb + (-12 if xb > xa else 12)
        parts.append(f'<path d="M{sx:.0f},{NY-24} Q{mx:.0f},{cy:.0f} {ex:.0f},{NY-24}" '
                     f'fill="none" stroke="var(--ember)" stroke-width="2" marker-end="url(#arrow)"/>')
        t = (e.get("ts") or "")[11:16]
        parts.append(f'<text x="{mx:.0f}" y="{cy+4:.0f}" class="elabel">'
                     f'{esc(t)} · {esc(e.get("logon_type_name","logon"))}</text>')

    # nodes
    for h in order:
        x = xs[h]
        meta = by_name[h]
        is_entry = (h == campaign.get("entry_host"))
        ip = meta["ips"][0] if meta["ips"] else ""
        cls = "node entry" if is_entry else "node"
        parts.append(f'<g class="{cls}">')
        parts.append(f'<rect x="{x-66:.0f}" y="{NY-26}" width="132" height="52" rx="10"/>')
        parts.append(f'<text x="{x:.0f}" y="{NY-4}" class="nhost">{esc(h)}</text>')
        parts.append(f'<text x="{x:.0f}" y="{NY+14}" class="nip">{esc(ip)}</text>')
        if is_entry:
            parts.append(f'<text x="{x:.0f}" y="{NY-34}" class="ntag">entry</text>')
        parts.append('</g>')

    parts.append('</svg>')
    return "".join(parts)


def render_case_html(campaign: dict) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    esc = html.escape

    graph = _case_graph_svg(campaign)

    # pivot chain
    chain_rows = ""
    for s in campaign["pivot_chain"]:
        if s["kind"] == "entry":
            chain_rows += (f'<div class="pstep"><div class="pdot">●</div><div class="pbody">'
                           f'<div class="phead">Entry · {esc(s["to"])}'
                           f'<span class="pts">{esc(s.get("ts",""))}</span></div>'
                           f'<div class="pev">{esc(s.get("evidence",""))}</div></div></div>')
        else:
            chain_rows += (f'<div class="pstep"><div class="pdot">→</div><div class="pbody">'
                           f'<div class="phead">{esc(s["from"])} → {esc(s["to"])}'
                           f'<span class="pts">{esc(s.get("ts",""))}</span></div>'
                           f'<div class="pmeta">{esc(s.get("logon_type","?"))} logon as '
                           f'{esc(s.get("account","?"))}</div>'
                           f'<div class="pev">{esc(s.get("evidence",""))}</div></div></div>')

    # shared-indicator links
    links = ""
    for e in campaign["undirected_edges"]:
        chips = "".join(f'<span class="chip">{esc(s["type"])}: {esc(s["value"])}</span>'
                        for s in e["shared"])
        links += (f'<div class="link"><span class="lhosts">{esc(e["hosts"][0])} ↔ '
                  f'{esc(e["hosts"][1])}</span><span class="lchips">{chips}</span></div>')

    # timeline
    tl = ""
    for r in campaign["timeline"]:
        src = f' <span class="tsrc">from {esc(r["src"])}</span>' if r.get("src") else ""
        tl += (f'<div class="trow"><span class="tts">{esc(r["ts"])}</span>'
               f'<span class="thost">{esc(r["host"])}</span>'
               f'<span class="tev">{esc(str(r.get("event_id","")))}</span>'
               f'<span class="tdetail">{esc(r.get("detail",""))}{src}</span></div>')

    # ATT&CK rollup
    att = ""
    for t in campaign["attack"]["techniques"]:
        hostchips = "".join(f'<span class="hchip">{esc(h)}</span>' for h in t["hosts"])
        att += (f'<div class="acell"><div class="atop"><span class="tid">{esc(t["id"])}</span>'
                f'<span class="acnt">{t["count"]}×</span></div>'
                f'<div class="tname">{esc(t["name"].split(":")[-1].strip())}</div>'
                f'<div class="ahosts">{hostchips}</div></div>')

    # custody panel
    cust = ""
    for c in campaign["custody"]:
        ok = c["ok"]
        cust += (f'<div class="crow {"cok" if ok else "cbad"}">'
                 f'<span class="cmark">{"✓" if ok else "✗"}</span>'
                 f'<span class="chost">{esc(c["host"])}</span>'
                 f'<span class="cpkg">{esc(c["package"])}</span>'
                 f'<span class="cfiles">{len(c["files"])} files verified</span></div>')
    rej = ""
    for r in campaign["rejected"]:
        rej += (f'<div class="crow cbad"><span class="cmark">✗</span>'
                f'<span class="cpkg">{esc(r["package"])}</span>'
                f'<span class="cfiles">{esc(r["reason"])}</span></div>')

    conf = campaign["confidence"]
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Campaign — case {esc(campaign['case_id'])}</title>
<style>
  :root {{ --ink:#15110d; --ink2:#1d1712; --line:#382e25; --paper:#efe6d8; --muted:#9b8f7e;
    --faint:#6f6453; --ember:#e0603a; --gold:#e0a838; --teal:#46c08e; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:radial-gradient(900px 500px at 82% -10%, rgba(70,192,142,.08), transparent 60%), var(--ink);
    color:var(--paper); font-family:"Spline Sans",system-ui,sans-serif; line-height:1.55; -webkit-font-smoothing:antialiased; }}
  .wrap {{ max-width:980px; margin:0 auto; padding:46px 24px 80px; }}
  .kicker {{ font-family:"JetBrains Mono",ui-monospace,monospace; font-size:12px; letter-spacing:.22em;
    text-transform:uppercase; color:var(--ember); margin:0 0 10px; }}
  h1 {{ font-family:"Fraunces",Georgia,serif; font-weight:600; font-size:clamp(28px,5vw,44px);
    line-height:1.04; margin:0 0 8px; letter-spacing:-.01em; }}
  .sub {{ color:var(--muted); max-width:64ch; margin:0 0 22px; }}
  .meta {{ display:flex; gap:10px; flex-wrap:wrap; margin-bottom:30px; }}
  .badge {{ font-family:"JetBrains Mono",ui-monospace,monospace; font-size:11px; letter-spacing:.06em;
    padding:6px 12px; border-radius:999px; border:1px solid var(--line); color:var(--muted); }}
  .badge.ok {{ color:var(--teal); border-color:rgba(70,192,142,.4); background:rgba(70,192,142,.07); }}
  h2 {{ font-family:"Fraunces",Georgia,serif; font-weight:500; font-size:22px; margin:32px 0 12px; }}
  section {{ margin-bottom:14px; }}
  .rc-callout {{ border:1px solid rgba(224,96,58,.35); background:rgba(224,96,58,.08);
    border-radius:14px; padding:18px 22px; margin-bottom:22px; }}
  .rc-label {{ font-family:"JetBrains Mono",ui-monospace,monospace; font-size:11px; letter-spacing:.14em;
    text-transform:uppercase; color:var(--ember); font-weight:700; }}
  .rc-conf {{ float:right; font-family:"JetBrains Mono",ui-monospace,monospace; font-size:10px; padding:2px 9px;
    border-radius:20px; text-transform:uppercase; letter-spacing:.06em; }}
  .rc-high {{ background:rgba(220,80,60,.25); color:#f2b8a8; }}
  .rc-medium {{ background:rgba(214,167,75,.22); color:#e6cf9a; }}
  .rc-low {{ background:rgba(140,140,140,.2); color:#cfcfcf; }}
  .rc-text {{ font-family:"Fraunces",Georgia,serif; font-size:18px; line-height:1.45; margin:10px 0 0; color:#f0e6d6; }}
  .graph-wrap {{ border:1px solid var(--line); border-radius:14px; padding:8px;
    background:linear-gradient(180deg,var(--ink2),transparent); margin-bottom:8px; }}
  svg.cgraph {{ width:100%; height:auto; display:block; }}
  .node rect {{ fill:var(--ink2); stroke:var(--line); stroke-width:1.5; }}
  .node.entry rect {{ stroke:var(--ember); stroke-width:2; fill:rgba(224,96,58,.10); }}
  .nhost {{ fill:var(--paper); font-family:"JetBrains Mono",ui-monospace,monospace; font-size:14px;
    font-weight:600; text-anchor:middle; }}
  .nip {{ fill:var(--muted); font-family:"JetBrains Mono",ui-monospace,monospace; font-size:10px; text-anchor:middle; }}
  .ntag {{ fill:var(--ember); font-family:"JetBrains Mono",ui-monospace,monospace; font-size:9px;
    letter-spacing:.14em; text-transform:uppercase; text-anchor:middle; }}
  .elabel {{ fill:#e7c98a; font-family:"JetBrains Mono",ui-monospace,monospace; font-size:10px; text-anchor:middle; }}
  .elabel.shared {{ fill:var(--gold); }}
  .legend {{ font-family:"JetBrains Mono",ui-monospace,monospace; font-size:10.5px; color:var(--faint);
    display:flex; gap:18px; padding:0 6px 6px; }}
  .legend .li b {{ color:var(--ember); }} .legend .ls b {{ color:var(--gold); }}
  .pstep {{ display:flex; gap:14px; align-items:flex-start; padding-bottom:14px; position:relative; }}
  .pstep:not(:last-child)::before {{ content:""; position:absolute; left:13px; top:28px; bottom:0; width:2px; background:var(--line); }}
  .pdot {{ flex:0 0 28px; height:28px; border-radius:50%; background:var(--ember); color:#1a120c;
    font-family:"JetBrains Mono",ui-monospace,monospace; font-weight:700; font-size:13px; display:flex;
    align-items:center; justify-content:center; z-index:1; }}
  .phead {{ font-family:"Fraunces",Georgia,serif; font-size:17px; color:#ede1cf; }}
  .pts {{ font-family:"JetBrains Mono",ui-monospace,monospace; font-size:11px; color:var(--faint); margin-left:10px; }}
  .pmeta {{ font-family:"JetBrains Mono",ui-monospace,monospace; font-size:11px; color:var(--gold); margin-top:3px; }}
  .pev {{ color:#c9bdac; font-size:12.5px; margin-top:4px; }}
  .link {{ display:flex; gap:12px; flex-wrap:wrap; align-items:baseline; padding:8px 0; border-bottom:1px solid var(--line); }}
  .lhosts {{ font-family:"JetBrains Mono",ui-monospace,monospace; font-size:12.5px; color:#ede1cf; flex:0 0 200px; }}
  .chip {{ display:inline-block; font-family:"JetBrains Mono",ui-monospace,monospace; font-size:10.5px;
    color:var(--gold); border:1px solid rgba(224,168,56,.32); border-radius:6px; padding:2px 7px; margin:2px 5px 0 0; }}
  .timeline {{ border:1px solid var(--line); border-radius:12px; overflow:hidden; }}
  .trow {{ display:grid; grid-template-columns:160px 90px 50px 1fr; gap:10px; padding:7px 12px;
    font-size:12px; border-bottom:1px solid var(--line); align-items:baseline; }}
  .trow:last-child {{ border-bottom:none; }}
  .tts {{ font-family:"JetBrains Mono",ui-monospace,monospace; color:var(--faint); }}
  .thost {{ font-family:"JetBrains Mono",ui-monospace,monospace; color:var(--ember); }}
  .tev {{ font-family:"JetBrains Mono",ui-monospace,monospace; color:var(--gold); }}
  .tdetail {{ color:#d8ccba; }} .tsrc {{ color:var(--teal); }}
  .matrix {{ display:flex; flex-wrap:wrap; gap:10px; }}
  .acell {{ flex:1 1 200px; min-width:200px; background:rgba(224,96,58,.08); border:1px solid rgba(224,96,58,.28);
    border-radius:8px; padding:10px 12px; }}
  .atop {{ display:flex; justify-content:space-between; align-items:baseline; }}
  .tid {{ font-family:"JetBrains Mono",ui-monospace,monospace; font-size:12px; font-weight:600; color:var(--ember); }}
  .acnt {{ font-family:"JetBrains Mono",ui-monospace,monospace; font-size:10px; color:var(--faint); }}
  .tname {{ font-size:11.5px; color:#d8ccba; margin:3px 0 6px; }}
  .hchip {{ display:inline-block; font-family:"JetBrains Mono",ui-monospace,monospace; font-size:10px;
    color:var(--teal); border:1px solid rgba(70,192,142,.3); border-radius:6px; padding:1px 6px; margin:2px 4px 0 0; }}
  .crow {{ display:grid; grid-template-columns:24px 110px 1fr auto; gap:10px; padding:8px 12px; font-size:12px;
    border:1px solid var(--line); border-radius:8px; margin-bottom:6px; align-items:baseline; }}
  .crow.cok {{ border-left:3px solid var(--teal); }} .crow.cbad {{ border-left:3px solid var(--ember); }}
  .cmark {{ font-weight:700; }} .cok .cmark {{ color:var(--teal); }} .cbad .cmark {{ color:var(--ember); }}
  .chost {{ font-family:"JetBrains Mono",ui-monospace,monospace; color:#ede1cf; }}
  .cpkg {{ font-family:"JetBrains Mono",ui-monospace,monospace; color:var(--muted); word-break:break-all; }}
  .cfiles {{ font-family:"JetBrains Mono",ui-monospace,monospace; color:var(--faint); }}
  footer {{ margin-top:44px; color:var(--faint); font-size:12px; font-family:"JetBrains Mono",ui-monospace,monospace; }}
</style></head>
<body><div class="wrap">
  <p class="kicker">Cross-host correlation · deterministic · air-gapped</p>
  <h1>Campaign — case {esc(campaign['case_id'])}</h1>
  <p class="sub">{campaign['host_count']} host(s) correlated from verified collection packages.
  Every edge, timeline entry, and finding traces to a specific event or artifact in a named package —
  no model is involved, and the evidence never left the host.</p>
  <div class="meta">
    <span class="badge ok">air-gapped · no egress</span>
    <span class="badge">{campaign['host_count']} hosts</span>
    <span class="badge">{len(campaign['directed_edges'])} lateral-movement edges</span>
    <span class="badge">{len(campaign['undirected_edges'])} shared-indicator links</span>
    <span class="badge">{campaign['attack']['technique_count']} ATT&amp;CK techniques</span>
  </div>

  <div class="rc-callout"><span class="rc-label">Campaign root cause</span>
    <span class="rc-conf rc-{conf}">{conf} confidence</span>
    <p class="rc-text">{esc(campaign['root_cause'])}</p></div>

  <h2>Host graph</h2>
  <div class="graph-wrap">{graph}</div>
  <div class="legend"><span class="li"><b>──▶</b> lateral movement (logon)</span>
    <span class="ls"><b>– –</b> shared indicator (C2 / hash / account)</span></div>

  <h2>Pivot chain</h2>
  <section>{chain_rows or '<p class="sub">No directed pivots reconstructed.</p>'}</section>

  <h2>Shared-indicator links</h2>
  <section>{links or '<p class="sub">No shared indicators across hosts.</p>'}</section>

  <h2>Unified timeline</h2>
  <section class="timeline">{tl}</section>

  <h2>MITRE ATT&amp;CK rollup</h2>
  <section class="matrix">{att}</section>

  <h2>Chain of custody</h2>
  <section>{cust}{rej}</section>

  <footer>generated {now} &nbsp;·&nbsp; air-gapped-forensic-analyst · cross-host correlation</footer>
</div></body></html>"""
