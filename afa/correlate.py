"""Cross-host correlation: turn a SET of collection packages into one campaign.

v1 analyzes a single host. v2 ingests a *case* — several packages — and correlates
across them, entirely locally and deterministically:

  * custody is verified on every package before use (a failure rejects + names it);
  * entities are extracted per host with the SAME deterministic logic the single-host
    tools use (corroborated C2, IOC hashes, accounts, persistence) — nothing reinvented;
  * undirected edges link hosts that share an indicator (C2 IP / file hash / account);
  * directed edges reconstruct lateral movement from 4624/4625 logons whose source
    resolves to another host in the case;
  * a unified, host-tagged timeline merges every host's events in time order;
  * a campaign root cause names the entry host and orders the pivot chain;
  * the ATT&CK map is rolled up across hosts, de-duplicated and host-attributed.

Every edge, timeline entry, and finding carries provenance: which package and which
underlying event/artifact it came from. No model is involved — this is pure analysis
over already-collected evidence, so the air-gap is never touched.
"""

from __future__ import annotations

import glob as _glob
from pathlib import Path

from .package import load_package, verify_package
from .rootcause import build_reconstruction
from .tools import (TACTIC_ORDER, _is_external, _is_suspicious_path, _remote_host,
                    account_changes, corroborated_c2, map_attack)

LOGON_EVENT_IDS = (4624, 4625)
LOGON_TYPE_NAME = {
    "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service",
    "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)", "11": "CachedInteractive",
}


# --------------------------------------------------------------------------
# package resolution
# --------------------------------------------------------------------------
def resolve_packages(spec) -> list[Path]:
    """Resolve a glob / directory / list into a sorted list of package paths.

    A directory that itself contains a manifest.json is one package; otherwise its
    immediate children that look like packages (a folder with manifest.json, or a
    .zip) are used. A glob string is expanded. A list/tuple is resolved per element.
    """
    if isinstance(spec, (list, tuple)):
        out: list[Path] = []
        for s in spec:
            out.extend(resolve_packages(s))
        # de-dup preserving order
        seen, uniq = set(), []
        for p in out:
            if str(p) not in seen:
                seen.add(str(p)); uniq.append(p)
        return uniq

    s = str(spec)
    p = Path(s)
    if p.is_dir():
        if (p / "manifest.json").exists():
            return [p]
        kids = []
        for child in sorted(p.iterdir()):
            if child.is_dir() and (child / "manifest.json").exists():
                kids.append(child)
            elif child.is_file() and child.suffix.lower() == ".zip":
                kids.append(child)
        return kids
    if p.is_file() and p.suffix.lower() == ".zip":
        return [p]
    # treat as a glob
    matches = sorted(Path(m) for m in _glob.glob(s))
    resolved: list[Path] = []
    for m in matches:
        resolved.extend(resolve_packages(m))
    return resolved


# --------------------------------------------------------------------------
# per-host entity extraction (reusing the single-host deterministic logic)
# --------------------------------------------------------------------------
def _account_name(s: str) -> str:
    """Bare account name: strip a DOMAIN\\ prefix and lower-case."""
    return (s or "").split("\\")[-1].strip().lower()


def _host_ips(ev) -> set[str]:
    """A host's own IP addresses, from the local side of its connections."""
    ips = set()
    for n in ev.network:
        loc = n.get("local") or ""
        ip = loc.rsplit(":", 1)[0] if ":" in loc else loc
        if ip and ip not in ("0.0.0.0", "::"):
            ips.add(ip)
    return ips


def _c2_entities(ev) -> dict[str, str]:
    """external C2 IP -> provenance string (reuses corroborated_c2)."""
    out: dict[str, str] = {}
    for c in corroborated_c2(ev):
        ip = _remote_host(c["endpoint"])
        if _is_external(ip):
            out.setdefault(ip, f"{c['endpoint']} via {c.get('via') or 'event'} (network.json)")
    return out


def _hash_entities(ev) -> dict[str, str]:
    """file hash -> provenance string (suspicious-path binaries only)."""
    out: dict[str, str] = {}
    for p in ev.processes:
        h = (p.get("hash") or "").strip()
        if h and "..." not in h and len(h) >= 16 and _is_suspicious_path(p.get("path", "")):
            out.setdefault(h, f"processes.json: {p.get('name','?')} ({p.get('path','')})")
    for pr in ev.programs:
        if pr.get("sha1") and _is_suspicious_path(pr.get("path", "")):
            out.setdefault(pr["sha1"], f"programs.json: {pr.get('name','?')} ({pr.get('path','')})")
    for s in ev.shimcache:
        if s.get("sha1") and _is_suspicious_path(s.get("path", "")):
            out.setdefault(s["sha1"], f"shimcache.json: {s.get('path','')}")
    return out


def _account_entities(ev) -> dict[str, str]:
    """attacker-relevant account -> provenance string.

    Created/modified accounts, accounts used in remote logons, and owners of
    suspicious-path processes — the accounts an investigator pivots on.
    """
    out: dict[str, str] = {}
    for a in account_changes(ev)["items"]:
        nm = _account_name((a.get("detail") or "").split(":")[-1])
        if nm:
            out.setdefault(nm, f"event {a.get('event_id')}: {a.get('action','changed')}")
    for e in ev.events:
        if e.get("event_id") in LOGON_EVENT_IDS and e.get("user"):
            nm = _account_name(e["user"])
            if nm:
                src = e.get("src_host") or e.get("src_ip") or "?"
                out.setdefault(nm, f"event {e['event_id']}: logon from {src}")
    for p in ev.processes:
        if p.get("user") and _is_suspicious_path(p.get("path", "")):
            nm = _account_name(p["user"])
            if nm:
                out.setdefault(nm, f"processes.json: owns {p.get('name','?')}")
    return out


def _earliest_event_ts(ev) -> str:
    times = sorted(e.get("ts", "") for e in ev.events if e.get("ts"))
    return times[0] if times else ""


def _host_model(path: Path, ev, manifest: dict, custody: dict) -> dict:
    recon = build_reconstruction(ev)
    attack = map_attack(ev)
    return {
        "host": ev.host,
        "package": str(path),
        "manifest": {k: manifest.get(k) for k in ("case_id", "operator", "collector_version",
                                                   "profile", "collected_at")},
        "host_meta": manifest.get("host", {}) or {},
        "custody": {"ok": custody["ok"],
                    "files": [{"name": f["name"], "ok": f["ok"]} for f in custody["files"]]},
        "ips": sorted(_host_ips(ev)),
        "recon": recon,
        "attack": attack,
        "c2": _c2_entities(ev),
        "hashes": _hash_entities(ev),
        "accounts": _account_entities(ev),
        "earliest_ts": _earliest_event_ts(ev),
        "_events": ev.events,   # kept for timeline + directed-edge reconstruction
    }


# --------------------------------------------------------------------------
# loading a case (with custody enforcement)
# --------------------------------------------------------------------------
def load_case(spec, verify: bool = True) -> tuple[list[dict], list[dict]]:
    """Load every package in the case, verifying custody. Returns (hosts, rejected).

    A package failing custody is rejected and named — never silently analyzed.
    """
    paths = resolve_packages(spec)
    hosts, rejected = [], []
    for p in paths:
        try:
            custody = verify_package(p)
        except Exception as exc:  # unreadable / not a package
            rejected.append({"package": str(p), "reason": f"could not read package: {exc}"})
            continue
        if verify and not custody["ok"]:
            bad = [f["name"] for f in custody["files"] if not f["ok"]]
            rejected.append({"package": str(p),
                             "reason": f"chain-of-custody check failed for: {', '.join(bad)}"})
            continue
        ev, manifest = load_package(p, verify=verify)
        hosts.append(_host_model(p, ev, manifest, custody))
    return hosts, rejected


# --------------------------------------------------------------------------
# edges
# --------------------------------------------------------------------------
def _shared_indicators(hosts: list[dict]) -> dict[str, list[dict]]:
    """value -> hosts sharing it, per indicator category, for values on 2+ hosts."""
    cats = {"c2": "c2", "hash": "hashes", "account": "accounts"}
    shared: dict[str, list[dict]] = {"c2": [], "hash": [], "account": []}
    for cat, attr in cats.items():
        index: dict[str, list[dict]] = {}
        for h in hosts:
            for value, prov in h[attr].items():
                index.setdefault(value, []).append({"host": h["host"], "evidence": prov})
        for value, members in sorted(index.items()):
            if len({m["host"] for m in members}) >= 2:
                shared[cat].append({"value": value, "hosts": members})
    return shared


def _undirected_edges(hosts: list[dict], shared: dict[str, list[dict]]) -> list[dict]:
    """Aggregate shared indicators into one undirected edge per host pair."""
    edges: dict[frozenset, dict] = {}
    for cat, items in shared.items():
        for item in items:
            members = item["hosts"]
            ev_by_host = {m["host"]: m["evidence"] for m in members}
            host_names = sorted(ev_by_host)
            for i in range(len(host_names)):
                for j in range(i + 1, len(host_names)):
                    a, b = host_names[i], host_names[j]
                    key = frozenset((a, b))
                    edge = edges.setdefault(key, {"hosts": [a, b], "shared": []})
                    edge["shared"].append({
                        "type": cat, "value": item["value"],
                        "evidence": {a: ev_by_host[a], b: ev_by_host[b]},
                    })
    return [edges[k] for k in sorted(edges, key=lambda s: sorted(s))]


def _directed_edges(hosts: list[dict]) -> list[dict]:
    """Lateral-movement edges from logon-source events resolving to another host."""
    ip_to_host: dict[str, str] = {}
    name_to_host: dict[str, str] = {}
    for h in hosts:
        name_to_host[h["host"].lower()] = h["host"]
        for ip in h["ips"]:
            ip_to_host[ip] = h["host"]

    edges = []
    for h in hosts:
        dest = h["host"]
        for e in h["_events"]:
            if e.get("event_id") not in LOGON_EVENT_IDS:
                continue
            src_ip, src_host = e.get("src_ip") or "", e.get("src_host") or ""
            source = ip_to_host.get(src_ip) or name_to_host.get(src_host.lower())
            if not source or source == dest:
                continue
            lt = str(e.get("logon_type") or "")
            edges.append({
                "source": source, "dest": dest, "ts": e.get("ts", ""),
                "account": _account_name(e.get("user", "")) or "?",
                "logon_type": lt, "logon_type_name": LOGON_TYPE_NAME.get(lt, lt or "?"),
                "src_ip": src_ip, "src_host": src_host,
                "evidence": f"{dest} {e.get('channel','Security')} event {e.get('event_id')}: "
                            f"{e.get('detail','')}",
                "package": h["package"],
            })
    edges.sort(key=lambda x: x["ts"])
    return edges


# --------------------------------------------------------------------------
# unified timeline
# --------------------------------------------------------------------------
def _timeline(hosts: list[dict]) -> list[dict]:
    rows = []
    for h in hosts:
        for e in h["_events"]:
            entry = {
                "ts": e.get("ts", ""), "host": h["host"], "package": h["package"],
                "event_id": e.get("event_id"), "process": e.get("process", ""),
                "detail": e.get("detail", ""),
            }
            if e.get("src_ip") or e.get("src_host"):
                entry["src"] = e.get("src_host") or e.get("src_ip")
            rows.append(entry)
    rows.sort(key=lambda r: (r["ts"] or "", r["host"]))
    return rows


# --------------------------------------------------------------------------
# ATT&CK rollup
# --------------------------------------------------------------------------
def _attack_rollup(hosts: list[dict]) -> dict:
    by_id: dict[str, dict] = {}
    for h in hosts:
        for t in h["attack"]["techniques"]:
            roll = by_id.setdefault(t["id"], {
                "id": t["id"], "name": t["name"], "tactics": t["tactics"],
                "hosts": [], "count": 0, "evidence": [],
            })
            if h["host"] not in roll["hosts"]:
                roll["hosts"].append(h["host"])
            roll["count"] += t["count"]
            for ev_str in t["evidence"]:
                tagged = f"[{h['host']}] {ev_str}"
                if tagged not in roll["evidence"]:
                    roll["evidence"].append(tagged)
    techniques = sorted(by_id.values(), key=lambda t: t["id"])
    for t in techniques:
        t["evidence"] = t["evidence"][:5]
        t["host_count"] = len(t["hosts"])
    tactics = [t for t in TACTIC_ORDER
               if any(t in tech["tactics"] for tech in techniques)]
    return {"technique_count": len(techniques), "tactics_covered": len(tactics),
            "tactics": tactics, "techniques": techniques}


# --------------------------------------------------------------------------
# campaign root cause
# --------------------------------------------------------------------------
def _campaign_rootcause(hosts: list[dict], directed: list[dict],
                        shared: dict[str, list[dict]]) -> dict:
    by_name = {h["host"]: h for h in hosts}
    dests = {e["dest"] for e in directed}
    sources = {e["source"] for e in directed}

    # entry candidates: hosts that are never a lateral-movement destination
    entry_candidates = [h for h in hosts if h["host"] not in dests]
    if not entry_candidates:
        entry_candidates = hosts
    entry_candidates.sort(key=lambda h: (h["earliest_ts"] or "9999"))
    entry = entry_candidates[0]["host"] if entry_candidates else (hosts[0]["host"] if hosts else "")

    # order the pivot chain by following directed edges from the entry in time order
    chain = []
    if directed:
        chain.append({"from": None, "to": entry, "ts": by_name.get(entry, {}).get("earliest_ts", ""),
                      "evidence": by_name.get(entry, {}).get("recon", {}).get("root_cause", ""),
                      "kind": "entry"})
        for e in directed:  # already ts-sorted
            chain.append({"from": e["source"], "to": e["dest"], "ts": e["ts"],
                          "account": e["account"], "logon_type": e["logon_type_name"],
                          "evidence": e["evidence"], "kind": "pivot"})

    shared_count = sum(len(v) for v in shared.values())
    n = len(hosts)
    entry_conf = by_name.get(entry, {}).get("recon", {}).get("root_cause_confidence", "low")

    if directed:
        reached = [entry] + [e["dest"] for e in directed]
        ordered = list(dict.fromkeys(reached))
        path = " -> ".join(ordered)
        accts = sorted({e["account"] for e in directed if e["account"] != "?"})
        acct_txt = f" reusing account '{', '.join(accts)}'" if accts else ""
        root_cause = (
            f"Campaign entry was {entry}; the intrusion then pivoted {path} via "
            f"network logons{acct_txt}. {by_name[entry]['recon']['root_cause']}"
        )
        confidence = "high" if (entry_conf in ("high", "medium") and shared_count) else "medium"
    elif shared_count:
        hosts_txt = ", ".join(h["host"] for h in hosts)
        root_cause = (
            f"No directed lateral movement could be reconstructed (logon-source data "
            f"absent or unresolved), but {n} hosts ({hosts_txt}) share attacker "
            f"indicators, so they are part of one campaign. Likely entry: {entry}."
        )
        confidence = "medium"
    else:
        root_cause = (
            f"{n} package(s) analyzed; no cross-host indicators or lateral movement were "
            f"found to link them into a single campaign."
        )
        confidence = "low"

    return {"entry_host": entry, "root_cause": root_cause, "confidence": confidence,
            "pivot_chain": chain}


# --------------------------------------------------------------------------
# top-level
# --------------------------------------------------------------------------
def correlate_case(spec, verify: bool = True) -> dict:
    """Build the full campaign model from a set of packages."""
    hosts, rejected = load_case(spec, verify=verify)

    shared = _shared_indicators(hosts)
    undirected = _undirected_edges(hosts, shared)
    directed = _directed_edges(hosts)
    timeline = _timeline(hosts)
    attack = _attack_rollup(hosts)
    rc = _campaign_rootcause(hosts, directed, shared)

    case_id = hosts[0]["manifest"].get("case_id", "?") if hosts else "?"
    host_views = [{
        "host": h["host"], "package": h["package"], "ips": h["ips"],
        "manifest": h["manifest"], "host_meta": h["host_meta"], "custody": h["custody"],
        "root_cause": h["recon"]["root_cause"],
        "root_cause_confidence": h["recon"]["root_cause_confidence"],
        "attack_techniques": h["attack"]["technique_count"],
        "c2": sorted(h["c2"]), "hashes": sorted(h["hashes"]), "accounts": sorted(h["accounts"]),
        "earliest_ts": h["earliest_ts"],
    } for h in hosts]

    return {
        "case_id": case_id,
        "host_count": len(hosts),
        "hosts": host_views,
        "rejected": rejected,
        "entry_host": rc["entry_host"],
        "root_cause": rc["root_cause"],
        "confidence": rc["confidence"],
        "pivot_chain": rc["pivot_chain"],
        "directed_edges": directed,
        "undirected_edges": undirected,
        "shared_indicators": shared,
        "timeline": timeline,
        "attack": attack,
        "custody": [{"package": h["package"], "host": h["host"],
                     "ok": h["custody"]["ok"], "files": h["custody"]["files"]} for h in hosts],
    }


def render_case_terminal(campaign: dict) -> str:
    """A concise text summary of the campaign for the CLI."""
    lines = [
        f"CROSS-HOST CORRELATION — case {campaign['case_id']}  ·  {campaign['host_count']} host(s)",
        "",
        f"{campaign['root_cause']}  [confidence: {campaign['confidence']}]",
        "",
    ]
    if campaign["pivot_chain"]:
        lines.append("Pivot chain:")
        for s in campaign["pivot_chain"]:
            if s["kind"] == "entry":
                lines.append(f"  * entry: {s['to']}  {s['ts']}")
            else:
                lines.append(f"  -> {s['from']} -> {s['to']}  {s['ts']}  "
                             f"[{s.get('logon_type','?')} logon as {s.get('account','?')}]")
        lines.append("")
    if campaign["undirected_edges"]:
        lines.append("Shared-indicator links:")
        for e in campaign["undirected_edges"]:
            kinds = ", ".join(sorted({s["type"] for s in e["shared"]}))
            vals = ", ".join(sorted({s["value"] for s in e["shared"]}))
            lines.append(f"  {e['hosts'][0]} <-> {e['hosts'][1]}  ({kinds}: {vals})")
        lines.append("")
    a = campaign["attack"]
    lines.append(f"ATT&CK rollup: {a['technique_count']} techniques across {a['tactics_covered']} tactics")
    lines.append(f"Unified timeline: {len(campaign['timeline'])} events across {campaign['host_count']} hosts")
    if campaign["rejected"]:
        lines.append("")
        lines.append("REJECTED packages (custody failure):")
        for r in campaign["rejected"]:
            lines.append(f"  ! {r['package']}: {r['reason']}")
    return "\n".join(lines)
