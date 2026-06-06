"""A grounded incident brief.

`build_brief` assembles the case findings by calling the same deterministic
tools the agent uses — so the brief is traceable, not invented. `render_brief`
turns that structure into an executive summary with no model required. A local
model can instead be handed the same structure to write the prose (see
`providers.LocalOllamaProvider.narrate`); either way it rests on the same facts.
"""

from __future__ import annotations

from .loader import Evidence
from .tools import (_remote_host, account_changes, analyze_command_intent, corroborated_c2,
                    detect_antiforensics, detect_lineage_anomalies, detect_lolbins,
                    detect_timestomping, filesystem_timeline, list_autoruns, map_attack,
                    scheduled_tasks, search_events, usb_history)


def build_brief(ev: Evidence) -> dict:
    autoruns = list_autoruns(ev)
    anti = detect_antiforensics(ev)
    usb = usb_history(ev)
    accts = account_changes(ev)
    tasks = scheduled_tasks(ev)
    attack = map_attack(ev)
    c2 = corroborated_c2(ev)
    lolbins = detect_lolbins(ev)
    intent = analyze_command_intent(ev)
    lineage = detect_lineage_anomalies(ev)
    timestomp = detect_timestomping(ev)
    deleted = filesystem_timeline(ev).get("deleted_suspicious", [])
    powershell = ([e for e in ev.events if e.get("process") == "powershell.exe"]
                  or [p for p in ev.processes if (p.get("name") or "").lower() == "powershell.exe"])

    key_findings: list[str] = []
    if powershell:
        ts = powershell[0].get("ts") or powershell[0].get("created", "")
        key_findings.append(f"Initial execution via encoded PowerShell at {ts}.")
    if lolbins["count"]:
        key_findings.append(f"Living-off-the-land binary abuse: {', '.join(lolbins['binaries'])} "
                            f"({lolbins['count']} command(s)).")
    decoded = [i for i in intent["items"] if i["decoded"] or i["obfuscated"]]
    if decoded:
        key_findings.append(f"Obfuscated/fileless execution: {len(decoded)} command(s) flagged "
                            f"({intent['decoded_count']} base64-decoded).")
    if lineage["count"]:
        key_findings.append("Anomalous process lineage: " +
                            "; ".join(i["reason"] for i in lineage["items"][:2]) + ".")
    if autoruns["suspicious_count"]:
        key_findings.append(f"{autoruns['suspicious_count']} suspicious persistence mechanism(s) "
                            "(Run key / service).")
    if tasks["count"]:
        key_findings.append(f"{tasks['count']} scheduled task(s) created for persistence.")
    if accts["count"]:
        names = ", ".join((a.get("detail") or "").split(":")[-1].strip() for a in accts["items"])
        key_findings.append(f"Local account(s) created: {names}.")
    if c2:
        ips = sorted({_remote_host(x["endpoint"]) for x in c2})
        key_findings.append(f"Outbound command-and-control to {', '.join(ips)}.")
    if usb["count"]:
        key_findings.append("Removable USB storage attached — potential exfiltration vector.")
    if anti["count"]:
        labels = "; ".join(sorted({i["label"] for i in anti["items"]}))
        key_findings.append(f"Anti-forensics: {labels}.")
    if timestomp["count"]:
        key_findings.append(f"Timestomping detected on {timestomp['count']} file(s) "
                            "(SI vs FN $MFT timestamps disagree).")
    if deleted:
        key_findings.append(f"{len(deleted)} deleted file record(s) for suspect binaries recovered "
                            "from $MFT (InUse=false).")

    # severity heuristic from breadth of activity
    tactics = attack["tactics_covered"]
    if anti["count"] and tactics >= 5:
        severity = "Critical"
        assessment = ("A hands-on-keyboard intrusion with established persistence, active C2, and "
                      "deliberate anti-forensics. Treat as a confirmed compromise.")
    elif tactics >= 3:
        severity = "High"
        assessment = "Multi-stage intrusion with persistence and likely C2; confirmed malicious activity."
    else:
        severity = "Moderate"
        assessment = "Suspicious activity warranting full investigation."

    return {
        "host": ev.host,
        "severity": severity,
        "assessment": assessment,
        "key_findings": key_findings,
        "attack": {"techniques": attack["technique_count"], "tactics": attack["tactics_covered"],
                   "ids": [t["id"] for t in attack["techniques"]]},
        "counts": {"events": len(ev.events), "registry": len(ev.registry)},
    }


def render_brief(brief: dict) -> str:
    """Deterministic executive summary, assembled from the findings (no model)."""
    lines = [
        f"INCIDENT BRIEF — {brief['host']}    Severity: {brief['severity']}",
        "",
        brief["assessment"],
        "",
        "Key findings:",
    ]
    lines += [f"  • {f}" for f in brief["key_findings"]]
    a = brief["attack"]
    lines += [
        "",
        f"ATT&CK: {a['techniques']} techniques across {a['tactics']} tactics "
        f"({', '.join(a['ids'])}).",
    ]
    return "\n".join(lines)
