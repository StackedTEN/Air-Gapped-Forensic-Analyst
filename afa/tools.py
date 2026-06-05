"""The forensic tool belt.

These are deterministic functions that parse the evidence. The agent does not
read raw artifacts and guess — it calls these tools, and every fact in an
answer is traceable to a tool result. That is the design's core safety property:
the model orchestrates the investigation; the tools supply the ground truth.

Each tool returns a JSON-serializable dict so it can be handed to a local LLM
through standard tool-calling and shown back to the analyst as provenance.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from .loader import Evidence

# Indicators of attacker activity used by a couple of heuristic tools.
SUSPICIOUS_PATHS = ("\\users\\public\\", "\\windows\\temp\\", "\\appdata\\local\\temp\\")
ANTIFORENSIC_EVENT_IDS = {1102, 104}  # security log cleared / system log cleared
PERSISTENCE_EVENT_IDS = {7045, 4697}  # service installed


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# --------------------------------------------------------------------------
# Registry tools
# --------------------------------------------------------------------------
def list_autoruns(ev: Evidence) -> dict:
    """List persistence mechanisms found in the registry (Run keys, services)."""
    items = [
        {"hive": r["hive"], "key": r["key"], "value": r["value_name"],
         "data": r["value_data"], "last_write": r["last_write"], "category": r["category"]}
        for r in ev.registry
        if r["category"] in ("run", "service")
    ]
    suspicious = [
        i for i in items
        if any(p in i["data"].lower() for p in SUSPICIOUS_PATHS) or "-enc" in i["data"].lower()
    ]
    return {"count": len(items), "suspicious_count": len(suspicious),
            "items": items, "suspicious": suspicious}


def query_registry(ev: Evidence, pattern: str) -> dict:
    """Search registry keys, value names, and data for a substring (case-insensitive)."""
    p = pattern.lower()
    items = [
        r for r in ev.registry
        if p in r["key"].lower() or p in r["value_name"].lower() or p in r["value_data"].lower()
    ]
    return {"pattern": pattern, "count": len(items), "items": items}


def usb_history(ev: Evidence) -> dict:
    """List removable-storage devices recorded in USBSTOR."""
    items = [r for r in ev.registry if r["category"] == "usbstor"]
    return {"count": len(items), "items": items}


# --------------------------------------------------------------------------
# Event-log tools
# --------------------------------------------------------------------------
def search_events(
    ev: Evidence,
    event_id: int | None = None,
    user: str | None = None,
    process: str | None = None,
    contains: str | None = None,
) -> dict:
    """Filter the event log by event_id, user, process, or a free-text substring."""
    out = []
    for x in ev.events:
        if event_id is not None and x["event_id"] != event_id:
            continue
        if user and user.lower() not in x.get("user", "").lower():
            continue
        if process and process.lower() not in x.get("process", "").lower():
            continue
        if contains:
            blob = " ".join(str(v) for v in x.values()).lower()
            if contains.lower() not in blob:
                continue
        out.append(x)
    return {"count": len(out), "items": out}


def count_events(ev: Evidence, event_id: int | None = None) -> dict:
    """Count events, optionally filtered by event_id."""
    n = sum(1 for x in ev.events if event_id is None or x["event_id"] == event_id)
    return {"event_id": event_id, "count": n}


def timeline(ev: Evidence, around: str | None = None, minutes: int = 60) -> dict:
    """Return events sorted by time, optionally within +/- a window of a timestamp."""
    items = sorted(ev.events, key=lambda x: x["ts"])
    if around:
        center = _ts(around)
        lo, hi = center - timedelta(minutes=minutes), center + timedelta(minutes=minutes)
        items = [x for x in items if lo <= _ts(x["ts"]) <= hi]
    return {"count": len(items),
            "items": [{"ts": x["ts"], "event_id": x["event_id"], "process": x["process"],
                       "detail": x["detail"]} for x in items]}


# --------------------------------------------------------------------------
# Cross-artifact tools
# --------------------------------------------------------------------------
def find_indicator(ev: Evidence, value: str) -> dict:
    """Search every artifact for an indicator (IP, filename, hash, service name)."""
    v = value.lower()
    reg_hits = [r for r in ev.registry if v in " ".join(str(x) for x in r.values()).lower()]
    evt_hits = [x for x in ev.events if v in " ".join(str(x) for x in x.values()).lower()]
    return {"indicator": value, "registry_hits": len(reg_hits), "event_hits": len(evt_hits),
            "registry": reg_hits, "events": evt_hits}


def detect_antiforensics(ev: Evidence) -> dict:
    """Look for evidence the attacker tried to cover their tracks (cleared logs, etc.)."""
    hits = [x for x in ev.events if x["event_id"] in ANTIFORENSIC_EVENT_IDS]
    return {"count": len(hits), "items": hits,
            "note": "Event ID 1102 indicates the Security audit log was cleared."}


# --------------------------------------------------------------------------
# Deeper forensic tools
# --------------------------------------------------------------------------
def process_tree(ev: Evidence) -> dict:
    """Reconstruct the parent/child process tree from process-creation events."""
    procs = [e for e in ev.events if e["event_id"] == 4688 and e["process"]]
    edges = [{"parent": e["parent_process"] or "?", "child": e["process"],
              "ts": e["ts"], "cmdline": e["cmdline"]} for e in procs]
    children: dict[str, list[str]] = {}
    all_children = set()
    for e in edges:
        children.setdefault(e["parent"], []).append(e["child"])
        all_children.add(e["child"])
    roots = [p for p in children if p not in all_children]

    lines: list[str] = []

    def walk(node: str, depth: int) -> None:
        lines.append(("  " * depth) + ("└ " if depth else "") + node)
        for c in children.get(node, []):
            walk(c, depth + 1)

    for r in roots:
        walk(r, 0)
    return {"count": len(edges), "roots": roots, "edges": edges, "tree": "\n".join(lines)}


def scheduled_tasks(ev: Evidence) -> dict:
    """List scheduled tasks created on the host (event ID 4698)."""
    items = [e for e in ev.events if e["event_id"] == 4698]
    return {"count": len(items), "items": items}


def account_changes(ev: Evidence) -> dict:
    """List local account changes: created (4720), deleted (4726), group add (4732)."""
    ids = {4720: "created", 4726: "deleted", 4732: "added to group"}
    items = [{**e, "action": ids[e["event_id"]]} for e in ev.events if e["event_id"] in ids]
    return {"count": len(items), "items": items}


# --- live-triage tools (populated by a collection package) ---
def _remote_host(remote: str) -> str:
    return remote.rsplit(":", 1)[0] if remote.count(":") == 1 else remote


def _is_external(host: str) -> bool:
    h = (host or "").strip()
    if not h or h in ("0.0.0.0", "::", "127.0.0.1", "::1"):
        return False
    if h.startswith(("10.", "192.168.", "127.", "169.254.", "fe80", "::")):
        return False
    if h.startswith("172."):
        try:
            if 16 <= int(h.split(".")[1]) <= 31:
                return False
        except (IndexError, ValueError):
            pass
    return True


def running_processes(ev: Evidence) -> dict:
    """List processes captured at collection time (live triage)."""
    return {"count": len(ev.processes), "items": ev.processes}


def network_connections(ev: Evidence, external_only: bool = False) -> dict:
    """List network connections; set external_only to show outbound to public IPs."""
    items = ev.network
    if external_only:
        items = [n for n in items if _is_external(_remote_host(n.get("remote", "")))]
    return {"count": len(items), "items": items}


def local_users(ev: Evidence) -> dict:
    """List local user accounts captured at collection time."""
    return {"count": len(ev.users), "items": ev.users}


def program_execution(ev: Evidence) -> dict:
    """Program-execution evidence (Amcache/Shimcache-style): what ran, when, hash."""
    return {"count": len(ev.programs), "items": ev.programs}


def powershell_activity(ev: Evidence) -> dict:
    """PowerShell execution: process-creation (4688) and ScriptBlock logs (4104)."""
    items = [e for e in ev.events
             if e.get("event_id") == 4104 or e.get("process") == "powershell.exe"]
    items += [{"ts": p.get("created", ""), "event_id": 0, "process": p.get("name"),
               "detail": p.get("cmdline", "")} for p in ev.processes
              if p.get("name", "").lower() == "powershell.exe"]
    return {"count": len(items), "items": items}


# --- MITRE ATT&CK mapping ---------------------------------------------------
TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]


def _e(e: dict) -> str:
    return f"{e['ts']} {e['process'] or 'event ' + str(e['event_id'])} — {e['detail'] or e.get('cmdline', '')}"


def _r(r: dict) -> str:
    return f"{r['hive']}\\{r['key']} :: {r['value_name']}={r['value_data']}"


# Each rule: technique id/name, the tactics it serves, and a matcher returning
# the concrete evidence rows that support it. A technique is "detected" only if
# its matcher finds evidence — so every mapping is traceable, never asserted.
ATTACK_RULES = [
    {"id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell",
     "tactics": ["Execution"],
     "match": lambda ev: [_e(e) for e in ev.events if e["process"] == "powershell.exe"]
                         + [f"{p.get('name','')} {p.get('cmdline','')}".strip()
                            for p in ev.processes if p.get("name", "").lower() == "powershell.exe"]},
    {"id": "T1547.001", "name": "Boot or Logon Autostart: Registry Run Keys",
     "tactics": ["Persistence", "Privilege Escalation"],
     "match": lambda ev: [_r(r) for r in ev.registry if r["category"] == "run"
                          and any(p in r["value_data"].lower() for p in SUSPICIOUS_PATHS)]},
    {"id": "T1543.003", "name": "Create or Modify System Process: Windows Service",
     "tactics": ["Persistence", "Privilege Escalation"],
     "match": lambda ev: [_r(r) for r in ev.registry if r["category"] == "service" and r["value_name"] == "ImagePath"]
                         + [_e(e) for e in ev.events if e["event_id"] == 7045]},
    {"id": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task",
     "tactics": ["Execution", "Persistence", "Privilege Escalation"],
     "match": lambda ev: [_e(e) for e in ev.events if e["event_id"] == 4698]},
    {"id": "T1136.001", "name": "Create Account: Local Account",
     "tactics": ["Persistence"],
     "match": lambda ev: [_e(e) for e in ev.events if e["event_id"] == 4720]},
    {"id": "T1036.005", "name": "Masquerading: Match Legitimate Name or Location",
     "tactics": ["Defense Evasion"],
     "match": lambda ev: [_e(e) for e in ev.events
                          if e["process"] == "svchost.exe" and "users\\public" in (e["cmdline"] or "").lower()]
                         + [_r(r) for r in ev.registry if "windefendsvc" in r["key"].lower() and r["value_name"] == "ImagePath"]
                         + [f"{p.get('name','')} {p.get('path','')}".strip() for p in ev.processes
                            if p.get("path") and any(s in p["path"].lower() for s in SUSPICIOUS_PATHS)]},
    {"id": "T1218.011", "name": "System Binary Proxy Execution: Rundll32",
     "tactics": ["Defense Evasion"],
     "match": lambda ev: [_e(e) for e in ev.events if e["process"] == "rundll32.exe"]},
    {"id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools",
     "tactics": ["Defense Evasion"],
     "match": lambda ev: [_r(r) for r in ev.registry if "defender" in r["key"].lower() and "disable" in r["value_name"].lower()]},
    {"id": "T1070.001", "name": "Indicator Removal: Clear Windows Event Logs",
     "tactics": ["Defense Evasion"],
     "match": lambda ev: [_e(e) for e in ev.events if e["event_id"] == 1102]},
    {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols",
     "tactics": ["Command and Control"],
     "match": lambda ev: [_e(e) for e in ev.events if e.get("dst_ip")]
                         + [f"{n.get('process') or 'pid ' + str(n.get('pid'))} -> {n.get('remote','')}"
                            for n in ev.network if _is_external(_remote_host(n.get("remote", "")))]},
    {"id": "T1052.001", "name": "Exfiltration Over Physical Medium: USB",
     "tactics": ["Exfiltration"],
     "match": lambda ev: [_r(r) for r in ev.registry if r["category"] == "usbstor" and r["value_name"] == "FriendlyName"]
                         + [_e(e) for e in ev.events if e["event_id"] == 6416]},
]


def map_attack(ev: Evidence) -> dict:
    """Map observed forensic evidence to MITRE ATT&CK techniques (with provenance)."""
    techniques = []
    for rule in ATTACK_RULES:
        evidence = rule["match"](ev)
        if evidence:
            techniques.append({"id": rule["id"], "name": rule["name"], "tactics": rule["tactics"],
                               "count": len(evidence), "evidence": evidence[:5]})
    tactics = [t for t in TACTIC_ORDER if any(t in tech["tactics"] for tech in techniques)]
    return {"technique_count": len(techniques), "tactics_covered": len(tactics),
            "tactics": tactics, "techniques": techniques}


# --------------------------------------------------------------------------
# Tool registry: name -> (callable, spec) for both the LLM and the dispatcher
# --------------------------------------------------------------------------
_REGISTRY = {
    "list_autoruns": (list_autoruns, {}),
    "query_registry": (query_registry, {"pattern": {"type": "string", "description": "substring to search for"}}),
    "usb_history": (usb_history, {}),
    "search_events": (search_events, {
        "event_id": {"type": "integer", "description": "Windows event ID, e.g. 4688"},
        "user": {"type": "string"}, "process": {"type": "string"},
        "contains": {"type": "string", "description": "free-text substring"}}),
    "count_events": (count_events, {"event_id": {"type": "integer"}}),
    "timeline": (timeline, {
        "around": {"type": "string", "description": "ISO timestamp to center on"},
        "minutes": {"type": "integer", "description": "window half-width in minutes"}}),
    "find_indicator": (find_indicator, {"value": {"type": "string", "description": "IP, filename, or hash"}}),
    "detect_antiforensics": (detect_antiforensics, {}),
    "process_tree": (process_tree, {}),
    "scheduled_tasks": (scheduled_tasks, {}),
    "account_changes": (account_changes, {}),
    "running_processes": (running_processes, {}),
    "network_connections": (network_connections, {"external_only": {"type": "boolean"}}),
    "local_users": (local_users, {}),
    "program_execution": (program_execution, {}),
    "powershell_activity": (powershell_activity, {}),
    "map_attack": (map_attack, {}),
}

_REQUIRED = {"query_registry": ["pattern"], "find_indicator": ["value"]}


def tool_specs() -> list[dict]:
    """Tool definitions in the OpenAI/Ollama function-calling schema."""
    specs = []
    for name, (fn, props) in _REGISTRY.items():
        specs.append({
            "type": "function",
            "function": {
                "name": name,
                "description": (fn.__doc__ or "").strip().split("\n")[0],
                "parameters": {"type": "object", "properties": props,
                               "required": _REQUIRED.get(name, [])},
            },
        })
    return specs


def dispatch(name: str, args: dict[str, Any], ev: Evidence) -> dict:
    """Execute a tool call by name. Unknown tools and bad args fail loudly."""
    if name not in _REGISTRY:
        return {"error": f"unknown tool: {name}"}
    fn, _ = _REGISTRY[name]
    try:
        return fn(ev, **(args or {}))
    except TypeError as exc:
        return {"error": f"bad arguments for {name}: {exc}"}


def tool_names() -> list[str]:
    return list(_REGISTRY)
