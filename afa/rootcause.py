"""Root-cause analysis: reconstruct the attack chain and name the root cause.

This is what makes the tool a forensic *analyst* rather than an artifact dump.
It correlates the deterministic tool outputs — process ancestry, timeline,
ATT&CK techniques, network, registry, accounts — into an ordered attack chain,
infers the most likely root cause with a stated confidence, extracts the IOCs an
investigator pivots on next, and is explicit about what's missing. Every element
traces back to a collected artifact; the reasoning is rule-based, not guessed.
"""

from __future__ import annotations

import re

from .loader import Evidence
from .tools import (SUSPICIOUS_PATHS, TACTIC_ORDER, _is_external, _remote_host,
                    _suspicious_proc_names, account_changes, corroborated_c2,
                    detect_antiforensics, list_autoruns, map_attack)

_ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

# What a malicious process's parent tells us about the initial-access vector.
INITIATOR_VECTOR = {
    "winword.exe": ("a malicious Microsoft Word document (phishing)", "high"),
    "excel.exe": ("a malicious Microsoft Excel document (phishing)", "high"),
    "outlook.exe": ("a malicious email attachment (phishing)", "high"),
    "w3wp.exe": ("exploitation of an IIS web application", "high"),
    "httpd.exe": ("exploitation of a web server", "high"),
    "nginx.exe": ("exploitation of a web server", "high"),
    "sqlservr.exe": ("exploitation of the SQL Server service", "high"),
    "wmiprvse.exe": ("remote WMI execution (lateral movement)", "high"),
    "services.exe": ("execution via a Windows service", "medium"),
    "taskeng.exe": ("execution via a scheduled task", "medium"),
    "svchost.exe": ("execution under a service-host process", "medium"),
    "explorer.exe": ("an interactive user session — phishing or hands-on-keyboard", "medium"),
}

PHASE_TITLE = {
    "Initial Access": "Initial access",
    "Execution": "Code execution",
    "Persistence": "Persistence established",
    "Privilege Escalation": "Privilege escalation",
    "Defense Evasion": "Defense evasion",
    "Credential Access": "Credential access",
    "Discovery": "Discovery",
    "Lateral Movement": "Lateral movement",
    "Collection": "Collection",
    "Command and Control": "Command-and-control",
    "Exfiltration": "Exfiltration",
    "Impact": "Impact",
}


def _earliest_ts(evidence: list[str]) -> str:
    found = sorted(m.group(0) for s in evidence for m in [_ISO.search(s)] if m)
    return found[0] if found else ""


def _parent_map(ev: Evidence) -> dict[str, str]:
    """child process name -> parent process name, from live processes and 4688 events."""
    by_pid = {p.get("pid"): p.get("name", "") for p in ev.processes}
    parents: dict[str, str] = {}
    for p in ev.processes:
        child, par = p.get("name", ""), by_pid.get(p.get("ppid"), "")
        if child:
            parents.setdefault(child.lower(), par.lower())
    for e in ev.events:
        if e.get("event_id") == 4688 and e.get("process"):
            parents.setdefault(e["process"].lower(), (e.get("parent_process") or "").lower())
    return parents


def _malicious_origin(ev: Evidence):
    """Find the earliest malicious process and its parent (the chain's foothold)."""
    cands = []
    for p in ev.processes:
        nm, cmd, path = p.get("name", "").lower(), (p.get("cmdline") or "").lower(), (p.get("path") or "").lower()
        if (nm == "powershell.exe" and ("-enc" in cmd or "hidden" in cmd)) or \
           any(s in path for s in SUSPICIOUS_PATHS):
            cands.append((p.get("created", ""), nm))
    for e in ev.events:
        if e.get("event_id") == 4688 and e.get("process") == "powershell.exe" and "enc" in (e.get("cmdline") or "").lower():
            cands.append((e.get("ts", ""), "powershell.exe"))
    cands = [c for c in cands if c[0]] or cands
    if not cands:
        return None
    cands.sort()
    return cands[0]  # (ts, name)


def _initial_access(ev: Evidence):
    origin = _malicious_origin(ev)
    if not origin:
        return ("Root cause could not be determined from the collected artifacts — "
                "no clear malicious execution was observed.", "low", "")
    ts, name = origin
    parent = _parent_map(ev).get(name, "")
    vector, conf = INITIATOR_VECTOR.get(parent, ("an unknown initial-access vector", "low"))
    when = f" at {ts}" if ts else ""
    via = f", launched by {parent}" if parent else ""
    return (f"Most likely root cause: {vector}. The earliest malicious activity was "
            f"{name}{when}{via}.", conf, ts)


def extract_iocs(ev: Evidence) -> dict:
    paths, accounts, persistence = set(), set(), []
    hashes = set()
    c2_list = corroborated_c2(ev)
    c2 = sorted({c["endpoint"] for c in c2_list})
    ips = sorted({_remote_host(c["endpoint"]) for c in c2_list})
    for p in ev.processes:
        path = p.get("path") or ""
        if any(s in path.lower() for s in SUSPICIOUS_PATHS):
            paths.add(path)
            h = (p.get("hash") or "").strip()
            if h and "..." not in h and len(h) >= 16:
                hashes.add(h)
    for pr in getattr(ev, "programs", []):
        if pr.get("sha1") and any(s in (pr.get("path") or "").lower() for s in SUSPICIOUS_PATHS):
            hashes.add(pr["sha1"])
    autoruns = list_autoruns(ev)
    for s in autoruns["suspicious"]:
        persistence.append(f"{s['hive']}\\{s['key']} :: {s['value']} = {s['data']}")
        if any(x in s["data"].lower() for x in SUSPICIOUS_PATHS):
            paths.add(s["data"])
    for a in account_changes(ev)["items"]:
        accounts.add(a["detail"].split(":")[-1].strip())
    return {"external_ips": ips, "file_hashes": sorted(hashes),
            "suspicious_paths": sorted(paths), "accounts": sorted(accounts),
            "persistence": persistence, "c2": c2}


def _gaps(ev: Evidence, iocs: dict, rc_conf: str) -> list[str]:
    gaps = []
    # collection-time warnings (e.g. Security log not collected) come first and loudest
    for w in getattr(ev, "collection_warnings", []):
        gaps.append(f"Collection warning: {w}")
    if rc_conf in ("medium", "low"):
        gaps.append("Initial-access vector was inferred from process ancestry; no email-gateway, "
                    "web-proxy, or EDR telemetry in this collection to confirm it.")
    if iocs["suspicious_paths"] and not iocs["file_hashes"]:
        gaps.append("Suspect binaries were not hashed — re-run the collector with -Profile full "
                    "to enable SHA-256 hashing for malware analysis and threat-intel pivoting.")
    if detect_antiforensics(ev)["count"]:
        gaps.append("The Security event log was cleared (T1070.001); earlier activity may be missing — "
                    "correlate with forwarded logs / SIEM to recover the gap.")
    if iocs["c2"]:
        gaps.append("C2 was observed as a live socket; pull proxy/DNS/firewall logs to scope the "
                    "connection's duration and any data transferred.")
    gaps.append("No file-system timeline ($MFT) was collected; the dropper's first-write time is unconfirmed.")
    return gaps


def _pivots(ev: Evidence, iocs: dict) -> list[str]:
    pivots = []
    for ip in iocs["external_ips"]:
        pivots.append(f"Hunt the fleet for any other host communicating with {ip}.")
    for path in iocs["suspicious_paths"][:3]:
        pivots.append(f"Acquire and analyze the binary at {path} (hash, sandbox detonation, YARA).")
    for acct in iocs["accounts"]:
        pivots.append(f"Audit logon history and group membership for account '{acct}' domain-wide.")
    if iocs["file_hashes"]:
        pivots.append("Submit collected hashes to threat intel and block at EDR.")
    return pivots


def build_reconstruction(ev: Evidence) -> dict:
    attack = map_attack(ev)
    root_cause, rc_conf, rc_ts = _initial_access(ev)
    iocs = extract_iocs(ev)

    # group techniques into ordered kill-chain steps
    by_phase: dict[str, dict] = {}
    for t in attack["techniques"]:
        phase = next((p for p in TACTIC_ORDER if p in t["tactics"]), t["tactics"][0])
        step = by_phase.setdefault(phase, {"phase": phase, "title": PHASE_TITLE.get(phase, phase),
                                           "techniques": [], "evidence": []})
        step["techniques"].append(t["id"])
        step["evidence"].extend(t["evidence"])
    chain = []
    for phase in TACTIC_ORDER:
        if phase in by_phase:
            s = by_phase[phase]
            ev_list = list(dict.fromkeys(s["evidence"]))[:4]
            chain.append({"phase": phase, "title": s["title"], "techniques": s["techniques"],
                          "evidence": ev_list, "ts": _earliest_ts(s["evidence"]),
                          "confidence": "high" if len(s["techniques"]) > 1 else "medium"})

    summary = (f"Confirmed compromise of {ev.host}: a {len(chain)}-phase intrusion spanning "
               f"{attack['technique_count']} ATT&CK techniques. {root_cause}")
    return {
        "host": ev.host, "root_cause": root_cause, "root_cause_confidence": rc_conf,
        "summary": summary, "chain": chain, "iocs": iocs,
        "gaps": _gaps(ev, iocs, rc_conf), "pivots": _pivots(ev, iocs),
        "attack": {"techniques": attack["technique_count"], "tactics": attack["tactics_covered"]},
    }


def render_rootcause(recon: dict) -> str:
    lines = [
        f"ROOT-CAUSE ANALYSIS — {recon['host']}",
        "",
        f"{recon['root_cause']}  [confidence: {recon['root_cause_confidence']}]",
        "",
        "Attack chain:",
    ]
    for i, s in enumerate(recon["chain"], 1):
        when = f" {s['ts']}" if s["ts"] else ""
        lines.append(f"  {i}. {s['title']}{when}  [{', '.join(s['techniques'])}]")
    io = recon["iocs"]
    lines += ["", "Indicators to pivot on:"]
    if io["c2"]:
        lines.append(f"  C2: {', '.join(io['c2'])}")
    if io["file_hashes"]:
        lines.append(f"  Hashes: {', '.join(io['file_hashes'])}")
    if io["suspicious_paths"]:
        lines.append(f"  Files: {', '.join(io['suspicious_paths'])}")
    if io["accounts"]:
        lines.append(f"  Accounts: {', '.join(io['accounts'])}")
    lines += ["", "What's missing (raises confidence if collected):"]
    lines += [f"  - {g}" for g in recon["gaps"]]
    lines += ["", "Recommended next steps:"]
    lines += [f"  - {p}" for p in recon["pivots"]]
    return "\n".join(lines)
