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
from .tools import (SUSPICIOUS_PATHS, TACTIC_ORDER, _is_external, _is_suspicious_path,
                    _remote_host, _suspicious_proc_names, account_changes, analyze_command_intent,
                    browser_history, corroborated_c2, detect_antiforensics,
                    detect_lineage_anomalies, detect_lolbins, detect_timestomping,
                    filesystem_timeline, list_autoruns, map_attack, prefetch_execution,
                    shimcache_entries, wmi_persistence)

_ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_URL_RE = re.compile(r"(?:https?|ftp)://[^\s'\"\)\]]+", re.I)

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
        nm, cmd, path = (p.get("name") or "").lower(), (p.get("cmdline") or "").lower(), (p.get("path") or "").lower()
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


def _downloaded_dropper(ev: Evidence, origin_name: str):
    """If a malicious binary was pulled down through the browser, that's the delivery.

    Returns (download_row, confidence, ran_as) when an executable download
    corroborates a suspicious-path binary or the malicious origin — the strongest
    initial-access signal the collection can offer without email-gateway telemetry.
    `ran_as` is the binary the download is shown to have become on disk.
    """
    bh = browser_history(ev)
    if not bh["executable_downloads"]:
        return None, "", ""
    susp_names = {(_basename(p.get("path", "")) or "").lower()
                  for p in ev.processes if _is_suspicious_path(p.get("path", ""))}
    susp_names |= {(_basename(f.get("path", "")) or "").lower()
                   for f in ev.filesystem if _is_suspicious_path(f.get("path", ""))}
    susp_names.discard("")
    for d in sorted(bh["executable_downloads"], key=lambda x: x.get("timestamp") or ""):
        tgt = (d.get("target_path") or d.get("url") or "")
        base = _basename(tgt)
        # high confidence when the downloaded file is the same one that later ran
        if base and (base.lower() in susp_names or base.lower() == (origin_name or "").lower()):
            return d, "high", base
        return d, "medium", base  # an exe was downloaded, but not provably the one that ran
    return None, "", ""


def _basename(p: str) -> str:
    return re.split(r"[\\/]", (p or "").strip())[-1] if p else ""


def _first_write(ev: Evidence, name: str) -> str:
    """Earliest file-system create time for a binary (the dropper's first write)."""
    nm = (name or "").lower()
    times = sorted(f.get("created", "") for f in ev.filesystem
                   if _basename(f.get("path", "")).lower() == nm and f.get("created"))
    return times[0] if times else ""


def _initial_access(ev: Evidence):
    origin = _malicious_origin(ev)
    if not origin:
        return ("Root cause could not be determined from the collected artifacts — "
                "no clear malicious execution was observed.", "low", "")
    ts, name = origin

    # A web download of the malicious file is the clearest delivery vector we can show.
    dl, dl_conf, ran_as = _downloaded_dropper(ev, name)
    if dl:
        ran_as = ran_as or name
        url = dl.get("url") or dl.get("target_path") or "an external URL"
        fw = _first_write(ev, ran_as)
        when_ts = dl.get("timestamp") or fw or ts
        when = f" at {when_ts}" if when_ts else ""
        firstrun = f" The dropper was first written to disk at {fw}." if fw else ""
        return (f"Most likely root cause: a malicious executable ({ran_as}) downloaded through the "
                f"web browser ({url}){when}, then executed on the host.{firstrun}", dl_conf, when_ts)

    # MFT can still pin the dropper's first write even without a download record
    fw = _first_write(ev, name)
    when_ts = fw or ts
    parent = _parent_map(ev).get(name, "")
    vector, conf = INITIATOR_VECTOR.get(parent, ("an unknown initial-access vector", "low"))
    when = f" at {when_ts}" if when_ts else ""
    via = f", launched by {parent}" if parent else ""
    firstrun = f" First written to disk at {fw}." if fw and fw != ts else ""
    return (f"Most likely root cause: {vector}. The earliest malicious activity was "
            f"{name}{when}{via}.{firstrun}", conf, when_ts)


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
    # deeper sources: shimcache hashes + dropped-file paths from the MFT timeline
    for s in shimcache_entries(ev)["suspicious"]:
        if s.get("sha1"):
            hashes.add(s["sha1"])
        if s.get("path"):
            paths.add(s["path"])
    for f in filesystem_timeline(ev)["dropped_files"]:
        if f.get("path"):
            paths.add(f["path"])
    autoruns = list_autoruns(ev)
    for s in autoruns["suspicious"]:
        persistence.append(f"{s['hive']}\\{s['key']} :: {s['value']} = {s['data']}")
        if any(x in (s.get("data") or "").lower() for x in SUSPICIOUS_PATHS):
            paths.add(s["data"])
    # WMI event-subscription persistence is its own mechanism
    for w in wmi_persistence(ev)["items"]:
        persistence.append(f"WMI: {w.get('filter_name','?')} -> {w.get('consumer_name','?')} "
                           f"({w.get('command') or w.get('query','')})")
    for a in account_changes(ev)["items"]:
        accounts.add((a.get("detail") or "").split(":")[-1].strip())
    # deleted dropper records ($MFT InUse=false) in user-writable paths are IOCs too
    for d in filesystem_timeline(ev).get("deleted_suspicious", []):
        if d.get("path"):
            paths.add(d["path"])
    # download cradles (LOLBin + decoded PowerShell) carry their own URLs
    download_urls = {d.get("url", "") for d in browser_history(ev)["executable_downloads"] if d.get("url")}
    for i in detect_lolbins(ev)["items"]:
        download_urls.update(_URL_RE.findall(i.get("command") or ""))
    for i in analyze_command_intent(ev)["items"]:
        if "download_cradle" in i.get("intent", []):
            download_urls.update(_URL_RE.findall((i.get("command") or "") + " " + (i.get("decoded") or "")))
    return {"external_ips": ips, "file_hashes": sorted(hashes),
            "suspicious_paths": sorted(paths), "accounts": sorted(accounts),
            "persistence": persistence, "c2": c2,
            "download_urls": sorted(u for u in download_urls if u)}


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
    anti = detect_antiforensics(ev)
    if anti["log_clear_count"]:
        # blind-spot quantification: name the clear time(s); events before are gone on-host
        for bs in anti["blind_spots"]:
            gaps.append(f"Visibility gap: {bs['note']}")
    if any("T1490" in i["techniques"] for i in anti["items"]):
        gaps.append("Volume Shadow Copies were deleted (T1490); on-host point-in-time recovery and "
                    "$MFT/$LogFile carving from snapshots are no longer available.")
    if any("T1070" == i["technique"] or "T1070" in i["techniques"] for i in anti["items"]
           if "usn" in (i.get("label", "").lower())):
        gaps.append("The USN change journal was deleted (T1070); recent file create/rename/delete "
                    "history is unrecoverable from the journal — rely on $MFT and forwarded telemetry.")
    ts_stomp = detect_timestomping(ev)
    if ts_stomp["count"]:
        names = ", ".join(t["path"] for t in ts_stomp["items"][:3])
        gaps.append(f"Timestomping detected (T1070.006) on: {names} — SI vs FN $MFT timestamps "
                    "disagree, so on-disk MAC times are unreliable; pivot on FN (0x30) times instead.")
    deleted = filesystem_timeline(ev).get("deleted_suspicious", [])
    if deleted:
        names = ", ".join(d.get("path", "") for d in deleted[:3])
        gaps.append(f"Deleted $MFT record(s) for suspect file(s) (T1070.004): {names} (InUse=false) — "
                    "the attacker deleted the dropper; carve resident data from $MFT/$LogFile.")
    if iocs["c2"]:
        gaps.append("C2 was observed as a live socket; pull proxy/DNS/firewall logs to scope the "
                    "connection's duration and any data transferred.")
    # the file-system timeline is now a collectable source: report it as present or absent
    fs = filesystem_timeline(ev)
    if not ev.filesystem:
        gaps.append("No file-system timeline ($MFT) was collected; the dropper's first-write time "
                    "is unconfirmed — re-run with -Profile full to capture it.")
    elif fs["earliest_drop"]:
        d = fs["earliest_drop"]
        gaps.append(f"File-system timeline confirms the dropper's first write: {d.get('path','')} "
                    f"at {d.get('created','')} (corroborate against $MFT $LogFile for resident-file recovery).")
    if not ev.browser:
        gaps.append("No browser history was collected; if delivery was web-based, the download URL "
                    "and referrer are unconfirmed.")
    if wmi_persistence(ev)["count"]:
        gaps.append("WMI event-subscription persistence (T1546.003) was found; enumerate the whole "
                    "root\\subscription namespace fleet-wide — it commonly survives reimaging of user data.")
    return gaps


def _pivots(ev: Evidence, iocs: dict) -> list[str]:
    pivots = []
    for ip in iocs["external_ips"]:
        pivots.append(f"Hunt the fleet for any other host communicating with {ip}.")
    for url in iocs.get("download_urls", []):
        pivots.append(f"Block {url} at the proxy and hunt other hosts that fetched it.")
    for path in iocs["suspicious_paths"][:3]:
        pivots.append(f"Acquire and analyze the binary at {path} (hash, sandbox detonation, YARA).")
    for acct in iocs["accounts"]:
        pivots.append(f"Audit logon history and group membership for account '{acct}' domain-wide.")
    if wmi_persistence(ev)["count"]:
        pivots.append("Remove the malicious WMI subscription (Remove-WmiObject on the filter, "
                      "consumer, and binding) and sweep the fleet for the same consumer name.")
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
    if io.get("download_urls"):
        lines.append(f"  Download URLs: {', '.join(io['download_urls'])}")
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
