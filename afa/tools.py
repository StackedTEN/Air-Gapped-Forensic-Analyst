"""The forensic tool belt.

These are deterministic functions that parse the evidence. The agent does not
read raw artifacts and guess — it calls these tools, and every fact in an
answer is traceable to a tool result. That is the design's core safety property:
the model orchestrates the investigation; the tools supply the ground truth.

Each tool returns a JSON-serializable dict so it can be handed to a local LLM
through standard tool-calling and shown back to the analyst as provenance.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
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
        if any(p in (i.get("data") or "").lower() for p in SUSPICIOUS_PATHS) or "-enc" in (i.get("data") or "").lower()
    ]
    return {"count": len(items), "suspicious_count": len(suspicious),
            "items": items, "suspicious": suspicious}


def query_registry(ev: Evidence, pattern: str) -> dict:
    """Search registry keys, value names, and data for a substring (case-insensitive)."""
    p = pattern.lower()
    items = [
        r for r in ev.registry
        if p in (r.get("key") or "").lower() or p in (r.get("value_name") or "").lower()
        or p in (r.get("value_data") or "").lower()
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
        if user and user.lower() not in (x.get("user") or "").lower():
            continue
        if process and process.lower() not in (x.get("process") or "").lower():
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


# detect_antiforensics is defined below (Detection Depth section) — it keeps the
# original 1102/104 log-clear detection and adds the broader anti-forensic toolkit.


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
    remote = remote or ""  # collected rows may carry a null remote
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


def _suspicious_proc_names(ev: Evidence) -> set:
    return {(p.get("name") or "").lower() for p in ev.processes
            if p.get("path") and any(s in p["path"].lower() for s in SUSPICIOUS_PATHS)}


def corroborated_c2(ev: Evidence) -> list[dict]:
    """External endpoints that actually look like C2 — not every :443 connection.

    Counted only when backed by a network/dst_ip event, or when the owning process
    is running from a suspicious location. This keeps benign outbound TLS from
    being mislabeled as command-and-control on a healthy host.
    """
    out, susp = [], _suspicious_proc_names(ev)
    for e in ev.events:
        if e.get("dst_ip") and _is_external(e["dst_ip"]):
            out.append({"endpoint": e["dst_ip"], "via": e.get("process") or "event"})
    for n in ev.network:
        if _is_external(_remote_host(n.get("remote", ""))) and (n.get("process") or "").lower() in susp:
            out.append({"endpoint": n.get("remote", ""), "via": n.get("process", "")})
    return out


def program_execution(ev: Evidence) -> dict:
    """Program-execution evidence (Amcache/Shimcache-style): what ran, when, hash."""
    return {"count": len(ev.programs), "items": ev.programs}


def powershell_activity(ev: Evidence) -> dict:
    """PowerShell execution: process-creation (4688) and ScriptBlock logs (4104)."""
    items = [e for e in ev.events
             if e.get("event_id") == 4104 or e.get("process") == "powershell.exe"]
    items += [{"ts": p.get("created", ""), "event_id": 0, "process": p.get("name"),
               "detail": p.get("cmdline", "")} for p in ev.processes
              if (p.get("name") or "").lower() == "powershell.exe"]
    return {"count": len(items), "items": items}


# --- deeper forensic tools (each backs one of the new sources) --------------
def _is_suspicious_path(p: str) -> bool:
    pl = (p or "").lower()
    return any(s in pl for s in SUSPICIOUS_PATHS) or "\\downloads\\" in pl or "\\programdata\\" in pl


_EXE_SUFFIXES = (".exe", ".dll", ".ps1", ".scr", ".js", ".hta", ".bat", ".vbs", ".zip", ".iso", ".lnk")


def prefetch_execution(ev: Evidence) -> dict:
    """Prefetch execution evidence: what ran, how many times, and when (first/last run)."""
    items = sorted(ev.prefetch, key=lambda p: p.get("last_run") or "", reverse=True)
    suspicious = [p for p in items if _is_suspicious_path(p.get("path", ""))]
    return {"count": len(items), "suspicious_count": len(suspicious),
            "items": items, "suspicious": suspicious}


def shimcache_entries(ev: Evidence) -> dict:
    """Amcache/Shimcache (AppCompatCache): programs present on the host — even if since deleted."""
    items = ev.shimcache
    suspicious = [s for s in items if _is_suspicious_path(s.get("path", ""))]
    return {"count": len(items), "suspicious_count": len(suspicious),
            "items": items, "suspicious": suspicious}


def filesystem_timeline(ev: Evidence, around: str | None = None, minutes: int = 60,
                        suspicious_only: bool = False) -> dict:
    """$MFT file-system timeline: file create/modify times — pins the dropper's first write."""
    def _key(r: dict) -> str:
        return r.get("created") or r.get("modified") or ""

    rows = ev.filesystem
    if suspicious_only:
        rows = [r for r in rows if _is_suspicious_path(r.get("path", ""))]
    rows = sorted(rows, key=_key)
    if around:
        center = _ts(around)
        lo, hi = center - timedelta(minutes=minutes), center + timedelta(minutes=minutes)
        kept = []
        for r in rows:
            try:
                if lo <= _ts(_key(r)) <= hi:
                    kept.append(r)
            except ValueError:
                pass
        rows = kept
    dropped = sorted((r for r in ev.filesystem if _is_suspicious_path(r.get("path", ""))), key=_key)
    deleted = sorted((r for r in rows if r.get("deleted")), key=_key)
    deleted_suspicious = [r for r in deleted if _is_suspicious_path(r.get("path", ""))]
    return {"count": len(rows), "items": rows, "dropped_files": dropped,
            "earliest_drop": dropped[0] if dropped else None,
            "deleted": deleted, "deleted_count": len(deleted),
            "deleted_suspicious": deleted_suspicious}


def browser_history(ev: Evidence, downloads_only: bool = False) -> dict:
    """Browser history and downloads — initial-access (download/drive-by) and web-exfil evidence."""
    rows = ev.browser
    if downloads_only:
        rows = [r for r in rows if r.get("type") == "download"]
    downloads = [r for r in ev.browser if r.get("type") == "download"]
    exe_downloads = [d for d in downloads
                     if (d.get("target_path") or d.get("url") or "").lower().endswith(_EXE_SUFFIXES)]
    return {"count": len(rows), "items": rows, "download_count": len(downloads),
            "downloads": downloads, "executable_downloads": exe_downloads}


def wmi_persistence(ev: Evidence) -> dict:
    """WMI event-subscription persistence: __EventFilter -> consumer bindings (T1546.003)."""
    items = ev.wmi
    cmd = [w for w in items
           if "commandline" in (w.get("consumer_type") or "").lower() or w.get("command")]
    return {"count": len(items), "command_consumers": len(cmd), "items": items}


# --------------------------------------------------------------------------
# Detection Depth — fileless / LOLBin / lineage / anti-forensics detectors.
#
# Each is a deterministic function over parsed evidence that returns its matches
# WITH provenance (which host, which event/artifact). They share one input
# surface — every place a command line can appear — so a finding always names
# the row it came from. No network, no model: decoding base64 is deterministic
# and the rulesets below are static and curated in-repo (no online LOLBAS fetch).
# --------------------------------------------------------------------------
def _command_records(ev: Evidence, include_scriptblocks: bool = True) -> list[dict]:
    """Every command line in the evidence, tagged with provenance.

    Covers 4688 process-creation command lines, 4104 PowerShell script blocks,
    and live-process command lines — so the detectors below run against both an
    events export and a live-triage package, degrading to whatever is present.
    """
    recs: list[dict] = []
    for e in ev.events:
        eid = e.get("event_id")
        host = e.get("computer") or ev.host
        if eid == 4688 and (e.get("cmdline") or ""):
            recs.append({"text": e.get("cmdline") or "", "process": (e.get("process") or ""),
                         "host": host, "ts": e.get("ts") or "", "source": "event 4688",
                         "parent": (e.get("parent_process") or ""), "event_id": 4688})
        if include_scriptblocks and eid == 4104:
            txt = (e.get("detail") or e.get("cmdline") or "")
            if txt:
                recs.append({"text": txt, "process": "powershell.exe", "host": host,
                             "ts": e.get("ts") or "", "source": "event 4104",
                             "parent": "", "event_id": 4104})
    for p in ev.processes:
        if (p.get("cmdline") or ""):
            recs.append({"text": p.get("cmdline") or "", "process": (p.get("name") or ""),
                         "host": ev.host, "ts": p.get("created") or "", "source": "processes.json",
                         "parent": "", "event_id": 0})
    return recs


def _prov(rec: dict) -> str:
    """A one-line provenance string for a command record: host · source · command."""
    host = rec.get("host") or "?"
    ts = (rec.get("ts") + " ") if rec.get("ts") else ""
    return f"{ts}{host} [{rec.get('source','?')}]: {rec.get('text','')[:200]}".strip()


# --- 3a. LOLBin abuse -------------------------------------------------------
# A curated static table of abused signed Windows binaries and the telltale
# argument patterns that distinguish abuse from benign use. Each rule is pure
# data: a binary token, a list of regex that must ALL be present (case-folded),
# the ATT&CK technique(s) it maps to, and a short label. Maintained in-repo —
# no online LOLBAS lookup, so it works on a zero-egress host.
LOLBIN_RULES: list[dict] = [
    {"bin": "certutil", "patterns": [r"certutil", r"(?:-|/)\s*urlcache", r"https?://|ftp://"],
     "techniques": ["T1105"], "label": "certutil URLCache download"},
    {"bin": "certutil", "patterns": [r"certutil", r"(?:-|/)\s*decode"],
     "techniques": ["T1140"], "label": "certutil decode (deobfuscation)"},
    {"bin": "bitsadmin", "patterns": [r"bitsadmin", r"/transfer"],
     "techniques": ["T1105"], "label": "bitsadmin /transfer download"},
    {"bin": "mshta", "patterns": [r"mshta", r"https?://|javascript:|vbscript:"],
     "techniques": ["T1218.005"], "label": "mshta remote/script execution"},
    {"bin": "rundll32", "patterns": [r"rundll32",
                                     r"javascript:|url\.dll|openurl|\\users\\public\\|\\windows\\temp\\|\\appdata\\|\\programdata\\"],
     "techniques": ["T1218.011"], "label": "rundll32 proxy execution"},
    {"bin": "regsvr32", "patterns": [r"regsvr32", r"scrobj\.dll"],
     "techniques": ["T1218.010"], "label": "regsvr32 scrobj.dll (squiblydoo)"},
    {"bin": "wmic", "patterns": [r"wmic", r"process\s+call\s+create|/node:"],
     "techniques": ["T1047"], "label": "wmic process call create / remote exec"},
    {"bin": "msiexec", "patterns": [r"msiexec", r"/i\b|/package", r"https?://"],
     "techniques": ["T1218.007", "T1105"], "label": "msiexec remote package install"},
    {"bin": "installutil", "patterns": [r"installutil", r"/logfile|/logtoconsole|/u\b|/installtype"],
     "techniques": ["T1218.004"], "label": "installutil uninstall-method execution"},
    {"bin": "regasm", "patterns": [r"regasm|regsvcs", r"/u\b|\.dll"],
     "techniques": ["T1218.009"], "label": "regasm/regsvcs proxy execution"},
    {"bin": "msbuild", "patterns": [r"msbuild", r"\.(?:xml|csproj|proj|targets)\b"],
     "techniques": ["T1127.001"], "label": "msbuild inline-task execution"},
    {"bin": "cmstp", "patterns": [r"cmstp", r"/s", r"\.inf"],
     "techniques": ["T1218.003"], "label": "cmstp /s .inf execution"},
    {"bin": "mavinject", "patterns": [r"mavinject", r"/injectrunning|\.dll"],
     "techniques": ["T1218.013", "T1055"], "label": "mavinject DLL injection"},
    {"bin": "esentutl", "patterns": [r"esentutl", r"/y", r"/vss|\\\\\.\\|\.dit\b"],
     "techniques": ["T1003"], "label": "esentutl /y VSS raw copy"},
    {"bin": "forfiles", "patterns": [r"forfiles", r"/c\b"],
     "techniques": ["T1218"], "label": "forfiles command proxy"},
    {"bin": "pcalua", "patterns": [r"pcalua", r"-a\b"],
     "techniques": ["T1218"], "label": "pcalua program-compat exec proxy"},
    {"bin": "control", "patterns": [r"control(?:\.exe)?", r"\.cpl",
                                    r"\\users\\public\\|\\windows\\temp\\|\\appdata\\|\\programdata\\"],
     "techniques": ["T1218.002"], "label": "control.exe .cpl from temp"},
]


def detect_lolbins(ev: Evidence) -> dict:
    """Living-off-the-land binary abuse: signed Windows tools run with attacker arguments.

    Matches a curated static ruleset over 4688 and live process command lines.
    Each hit names the binary, the offending command line, host + source, and the
    ATT&CK technique — so every finding is traceable, never asserted.
    """
    items: list[dict] = []
    for rec in _command_records(ev, include_scriptblocks=False):
        text = (rec["text"] or "")
        low = text.lower()
        for rule in LOLBIN_RULES:
            if all(re.search(p, low) for p in rule["patterns"]):
                techs = list(rule["techniques"])
                if rule["bin"] == "regsvr32" and "http" in low and "T1105" not in techs:
                    techs.append("T1105")
                items.append({
                    "binary": rule["bin"], "label": rule["label"], "techniques": techs,
                    "command": text, "host": rec["host"], "ts": rec["ts"],
                    "source": rec["source"], "provenance": _prov(rec),
                })
    binaries = sorted({i["binary"] for i in items})
    return {"count": len(items), "binaries": binaries, "items": items}


# --- 3b. Command-line / script-block deobfuscation + intent -----------------
_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_ENC_FLAG_RE = re.compile(r"(?:-|/)(?:e|ec|enc|encod|encodedcommand)\b\s*[:=]?\s*", re.I)

# intent -> (compiled patterns, technique ids). Pure data; matched against the
# raw command AND any base64 we decode out of it.
INTENT_RULES: list[dict] = [
    {"tag": "download_cradle",
     "patterns": [r"net\.webclient", r"downloadstring", r"downloadfile", r"downloaddata",
                  r"invoke-webrequest", r"\biwr\b", r"\bcurl\b", r"\bwget\b",
                  r"start-bitstransfer", r"certutil.*https?://"],
     "techniques": ["T1105"], "label": "remote download cradle"},
    {"tag": "in_memory_exec",
     "patterns": [r"\biex\b", r"invoke-expression", r"\[scriptblock\]::create", r"icm\s+-script"],
     "techniques": ["T1059.001"], "label": "in-memory script execution (IEX)"},
    {"tag": "reflective_load",
     "patterns": [r"\[reflection\.assembly\]::load", r"\[appdomain\]::", r"loadlibrary"],
     "techniques": ["T1055"], "label": "reflective assembly load"},
    {"tag": "amsi_etw_bypass",
     "patterns": [r"amsiutils", r"amsiinitfailed", r"\[ref\]\.assembly\.gettype",
                  r"etweventwrite", r"amsiscanbuffer"],
     "techniques": ["T1562.001"], "label": "AMSI / ETW bypass"},
    {"tag": "process_injection",
     "patterns": [r"virtualalloc", r"writeprocessmemory", r"createremotethread",
                  r"createthread", r"\[dllimport"],
     "techniques": ["T1055"], "label": "in-memory injection primitives"},
]

# stealth launch flags (PowerShell) — not malicious alone, but corroborating.
_STEALTH_RE = [
    (r"(?:-|/)w(?:indowstyle)?\s+hidden|-w\s+hidden", "hidden window"),
    (r"(?:-|/)nop(?:rofile)?\b", "no profile"),
    (r"(?:-|/)(?:ep|executionpolicy)\s+bypass|-ep\s+bypass", "execution-policy bypass"),
    (r"(?:-|/)noni|noninteractive", "non-interactive"),
]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _try_b64(blob: str) -> str:
    """Best-effort base64 decode: UTF-16LE first (PowerShell -enc), then UTF-8.

    Returns "" when the blob is not valid base64 or decodes to mostly non-text.
    Deterministic and offline — decoding bytes already on the host, never fetching.
    """
    s = blob.strip()
    pad = (-len(s)) % 4
    try:
        raw = base64.b64decode(s + ("=" * pad), validate=False)
    except (binascii.Error, ValueError):
        return ""
    for enc in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
        if text and printable / len(text) >= 0.85:
            return text.replace("\x00", "")
    return ""


def _decode_command(text: str) -> tuple[str, bool]:
    """Decode -EncodedCommand / FromBase64String blobs out of a command.

    Returns (decoded_concatenation, had_encoding). had_encoding is True whenever an
    encoding flag/primitive was present even if the blob itself didn't decode.
    """
    decoded: list[str] = []
    had_encoding = False
    low = text.lower()
    if _ENC_FLAG_RE.search(text) or "frombase64string" in low:
        had_encoding = True
    # decode every long base64 token; that captures both -enc <blob> and
    # [Convert]::FromBase64String('<blob>') forms without parsing the syntax.
    for m in _B64_RE.finditer(text):
        dec = _try_b64(m.group(0))
        if dec:
            decoded.append(dec)
    return ("\n".join(decoded), had_encoding)


def analyze_command_intent(ev: Evidence) -> dict:
    """Decode obfuscated commands and classify intent (download/exec/inject/bypass).

    Decodes PowerShell -EncodedCommand and FromBase64String blobs (deterministic,
    offline), re-scans the cleartext for intent patterns, and flags obfuscation by
    entropy / reassembly tells. Each result carries the matched intent tags, the
    obfuscation flag, the decoded text, and provenance.
    """
    items: list[dict] = []
    for rec in _command_records(ev, include_scriptblocks=True):
        text = rec["text"] or ""
        low = text.lower()
        decoded, had_encoding = _decode_command(text)
        scan = (low + "\n" + decoded.lower()) if decoded else low

        tags: list[str] = []
        techniques: list[str] = []
        for rule in INTENT_RULES:
            if any(re.search(p, scan) for p in rule["patterns"]):
                tags.append(rule["tag"])
                for t in rule["techniques"]:
                    if t not in techniques:
                        techniques.append(t)

        # obfuscation heuristics
        obf_reasons: list[str] = []
        if had_encoding:
            obf_reasons.append("base64-encoded command")
        token = max((m.group(0) for m in _B64_RE.finditer(text)), key=len, default="")
        if len(token) >= 40 and _shannon_entropy(token) >= 4.0:
            obf_reasons.append(f"high-entropy blob ({_shannon_entropy(token):.1f} bits)")
        if text.count("`") >= 4:
            obf_reasons.append("backtick obfuscation")
        if re.search(r"\[char\]\s*\d|-join|\[string\]::join|-split", low):
            obf_reasons.append("char-array / join-split reassembly")
        if re.search(r"\{\d+\}\{\d+\}|-f\s*['\"]", low):
            obf_reasons.append("format-string obfuscation")
        if len(token) >= 200:
            obf_reasons.append("very long single-line base64")
        stealth = [name for pat, name in _STEALTH_RE if re.search(pat, low)]

        if had_encoding or token:
            for t in ("T1027", "T1140"):
                if t not in techniques:
                    techniques.append(t)
        if obf_reasons and "T1027" not in techniques:
            techniques.append("T1027")

        if tags or obf_reasons or stealth:
            items.append({
                "command": text, "decoded": decoded, "intent": tags,
                "obfuscated": bool(obf_reasons), "obfuscation": obf_reasons,
                "stealth_flags": stealth, "techniques": techniques,
                "host": rec["host"], "ts": rec["ts"], "source": rec["source"],
                "provenance": _prov(rec),
            })
    decoded_count = sum(1 for i in items if i["decoded"])
    return {"count": len(items), "decoded_count": decoded_count, "items": items}


# --- 3c. Process-lineage anomalies ------------------------------------------
_OFFICE = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe")
_WEB_SERVERS = ("w3wp.exe", "tomcat.exe", "tomcat9.exe", "nginx.exe", "httpd.exe", "apache.exe")
_SHELLS = ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
           "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe", "certutil.exe")
_SCRIPT_SHELLS = ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe")
_PROXY_PARENTS = ("mshta.exe", "regsvr32.exe", "rundll32.exe")
_LSASS_TOOLS = ("procdump.exe", "procdump64.exe", "comsvcs.dll", "rundll32.exe", "taskmgr.exe",
                "sqldumper.exe", "werfault.exe")


def _lineage_pairs(ev: Evidence) -> list[dict]:
    """(parent, child) pairs with provenance, from live processes (ppid) and 4688."""
    pairs: list[dict] = []
    by_pid = {p.get("pid"): p for p in ev.processes}
    for p in ev.processes:
        parent = by_pid.get(p.get("ppid"))
        child_name = (p.get("name") or "")
        if child_name:
            pairs.append({
                "parent": ((parent or {}).get("name") or "").lower(),
                "child": child_name.lower(),
                "child_cmdline": p.get("cmdline") or "", "parent_cmdline": (parent or {}).get("cmdline") or "",
                "host": ev.host, "ts": p.get("created") or "", "source": "processes.json",
            })
    for e in ev.events:
        if e.get("event_id") == 4688 and (e.get("process") or ""):
            pairs.append({
                "parent": (e.get("parent_process") or "").lower(),
                "child": (e.get("process") or "").lower(),
                "child_cmdline": e.get("cmdline") or "", "parent_cmdline": "",
                "host": e.get("computer") or ev.host, "ts": e.get("ts") or "", "source": "event 4688",
            })
    return pairs


def detect_lineage_anomalies(ev: Evidence) -> dict:
    """Anomalous parent→child process lineage (e.g. Office or a web server spawning a shell).

    Reads the process tree (live ppid→pid) and 4688 parent/child. Flags the classic
    execution-lineage tells of fileless intrusion; each finding names both processes,
    their command lines, host + source, and the ATT&CK technique.
    """
    items: list[dict] = []
    for pr in _lineage_pairs(ev):
        parent, child = pr["parent"], pr["child"]
        low = (pr["child_cmdline"] or "").lower()
        reason = techniques = None
        # lsass access is a process-level tell that needs no known parent
        if "lsass" in low and (child in _LSASS_TOOLS or "comsvcs" in low or "minidump" in low):
            reason = f"{child or 'a process'} accessed lsass (credential dumping): {pr['child_cmdline'][:120]}"
            techniques = ["T1003.001"]
        elif not parent or not child:
            continue
        elif parent in _OFFICE and child in _SHELLS:
            reason = f"Office application {parent} spawned {child}"
            techniques = ["T1566.001", "T1059"]
        elif parent in _WEB_SERVERS and child in _SHELLS:
            reason = f"web server {parent} spawned {child} (web shell)"
            techniques = ["T1059.003" if child == "cmd.exe" else "T1059", "T1505.003"]
        elif parent == "wmiprvse.exe" and child in _SCRIPT_SHELLS:
            reason = f"WMI provider {parent} spawned {child} (remote WMI execution)"
            techniques = ["T1047", "T1059"]
        elif parent in _PROXY_PARENTS and child in _SCRIPT_SHELLS:
            reason = f"proxy binary {parent} spawned {child}"
            techniques = ["T1218", "T1059"]
        elif parent in ("services.exe", "svchost.exe") and child in _SCRIPT_SHELLS:
            reason = f"service host {parent} spawned interactive {child}"
            techniques = ["T1059", "T1543.003"]
        if reason and techniques:
            arrow = f"{parent or '?'} -> {child or '?'}"
            prov = (f"{(pr['ts'] + ' ') if pr['ts'] else ''}{pr['host']} [{pr['source']}]: "
                    f"{arrow}").strip()
            items.append({
                "parent": parent, "child": child, "reason": reason, "techniques": techniques,
                "parent_cmdline": pr["parent_cmdline"], "child_cmdline": pr["child_cmdline"],
                "host": pr["host"], "ts": pr["ts"], "source": pr["source"], "provenance": prov,
            })
    return {"count": len(items), "items": items}


# --- 3d. Anti-forensics, deepened + timestomp -------------------------------
# command-line tradecraft for covering tracks, as static regex + technique data.
ANTIFORENSIC_CMD_RULES: list[dict] = [
    {"patterns": [r"vssadmin", r"delete\s+shadows"], "techniques": ["T1490"],
     "label": "VSS shadow-copy deletion"},
    {"patterns": [r"wmic", r"shadowcopy", r"delete"], "techniques": ["T1490"],
     "label": "WMIC shadowcopy deletion"},
    {"patterns": [r"vssadmin", r"resize\s+shadowstorage"], "techniques": ["T1490"],
     "label": "VSS shadowstorage resize (recovery sabotage)"},
    {"patterns": [r"\bwbadmin\b", r"delete\s+(?:catalog|systemstatebackup|backup)"],
     "techniques": ["T1490"], "label": "wbadmin backup deletion"},
    {"patterns": [r"bcdedit", r"recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures"],
     "techniques": ["T1490"], "label": "bcdedit recovery disable"},
    {"patterns": [r"fsutil", r"usn", r"deletejournal"], "techniques": ["T1070"],
     "label": "USN change-journal deletion"},
    {"patterns": [r"wevtutil", r"\bcl\b|clear-log"], "techniques": ["T1070.001"],
     "label": "wevtutil event-log clear"},
    {"patterns": [r"clear-eventlog"], "techniques": ["T1070.001"], "label": "Clear-EventLog"},
    {"patterns": [r"remove-eventlog"], "techniques": ["T1070.001"], "label": "Remove-EventLog"},
    {"patterns": [r"(?:sc|net)\s+stop\s+eventlog|stop-service\s+.*eventlog"],
     "techniques": ["T1562.001"], "label": "EventLog service stop"},
    {"patterns": [r"cipher", r"/w"], "techniques": ["T1070.004"], "label": "cipher /w secure wipe"},
    {"patterns": [r"\bsdelete\b"], "techniques": ["T1070.004"], "label": "sdelete secure wipe"},
    {"patterns": [r"set-mppreference", r"disable"], "techniques": ["T1562.001"],
     "label": "Defender tampering (Set-MpPreference -Disable...)"},
    {"patterns": [r"add-mppreference", r"exclusionpath|exclusionextension"],
     "techniques": ["T1562.001"], "label": "Defender exclusion added"},
    {"patterns": [r"clear-history"], "techniques": ["T1070"], "label": "PowerShell history clear"},
    {"patterns": [r"del\b.*consolehost_history|remove-item.*consolehost_history"],
     "techniques": ["T1070"], "label": "PSReadLine history file deletion"},
]

# service-control events that can signal EventLog tampering (best-effort).
_SVC_TAMPER_IDS = {7035, 7036, 7040}


def detect_antiforensics(ev: Evidence) -> dict:
    """Evidence the attacker tried to cover their tracks.

    Keeps the original log-clearing detection (events 1102 / 104) and adds, from
    command lines, the broader anti-forensic toolkit: VSS / shadow deletion,
    USN-journal deletion, event-log tampering, secure wipe, Defender tampering,
    and history clearing — each with its host, source, and ATT&CK technique. When
    a log was cleared, it also quantifies the resulting visibility blind spot.
    """
    log_clears = [x for x in ev.events if x.get("event_id") in ANTIFORENSIC_EVENT_IDS]
    items: list[dict] = []
    for e in log_clears:
        eid = e.get("event_id")
        items.append({
            "technique": "T1070.001", "techniques": ["T1070.001"],
            "label": "Security audit log cleared" if eid == 1102 else "System event log cleared",
            "command": "", "host": e.get("computer") or ev.host, "ts": e.get("ts") or "",
            "source": f"event {eid}", "event_id": eid,
            "provenance": f"{e.get('ts','')} {e.get('computer') or ev.host} event {eid}: "
                          f"{e.get('detail','')}".strip(),
        })
    for rec in _command_records(ev, include_scriptblocks=True):
        low = (rec["text"] or "").lower()
        for rule in ANTIFORENSIC_CMD_RULES:
            if all(re.search(p, low) for p in rule["patterns"]):
                items.append({
                    "technique": rule["techniques"][0], "techniques": list(rule["techniques"]),
                    "label": rule["label"], "command": rec["text"], "host": rec["host"],
                    "ts": rec["ts"], "source": rec["source"], "event_id": rec["event_id"],
                    "provenance": _prov(rec),
                })

    # blind-spot quantification: each cleared log opens a window before it during
    # which events are unavailable on this host.
    blind_spots = [{
        "host": c["host"], "cleared_at": c["ts"], "event_id": c["event_id"],
        "note": (f"{c['label']} at {c['ts'] or 'unknown time'} on {c['host']}; events before "
                 "this are unavailable on-host — recover from forwarded logs / SIEM."),
    } for c in items if c.get("event_id") in ANTIFORENSIC_EVENT_IDS]

    return {"count": len(items), "items": items, "blind_spots": blind_spots,
            "log_clear_count": len(log_clears),
            "note": "Event ID 1102 indicates the Security audit log was cleared."}


# --- 3d. Timestomp detection (SI 0x10 vs FN 0x30) ---------------------------
def _frac(ts: str) -> str:
    """Fractional-seconds component of an ISO timestamp ('' if none)."""
    m = re.search(r"\d{2}:\d{2}:\d{2}\.(\d+)", ts or "")
    return m.group(1).rstrip("0") if m else ""


def detect_timestomping(ev: Evidence) -> dict:
    """Timestomping: $STANDARD_INFORMATION (0x10) vs $FILE_NAME (0x30) disagreement.

    Flags a file when its SI-created time precedes its FN-created time (impossible
    naturally — FN is set at record creation), or when the SI timestamps have
    zeroed sub-seconds while FN does not (a classic timestomp tell). Cites the
    SI-vs-FN comparison as evidence. Degrades gracefully: rows without FN (0x30)
    timestamps are skipped, never guessed.
    """
    items: list[dict] = []
    for f in ev.filesystem:
        si_c = f.get("created") or ""
        fn_c = f.get("fn_created") or ""
        if not fn_c:                       # no $FILE_NAME data — cannot compare
            continue
        reasons: list[str] = []
        if si_c and fn_c and si_c < fn_c:
            reasons.append(f"SI-created ({si_c}) precedes FN-created ({fn_c}) — impossible naturally")
        si_m, fn_m = f.get("modified") or "", f.get("fn_modified") or ""
        if si_c and fn_c and not _frac(si_c) and _frac(fn_c):
            reasons.append("SI timestamps have zeroed sub-seconds while FN does not")
        elif si_m and fn_m and not _frac(si_m) and _frac(fn_m):
            reasons.append("SI modified has zeroed sub-seconds while FN does not")
        if reasons:
            items.append({
                "path": f.get("path") or "", "name": f.get("name") or "",
                "si_created": si_c, "fn_created": fn_c, "si_modified": si_m, "fn_modified": fn_m,
                "techniques": ["T1070.006"], "reasons": reasons, "host": ev.host,
                "source": "filesystem.json ($MFT SI/FN)",
                "provenance": f"{ev.host} [$MFT]: {f.get('path','')} — {'; '.join(reasons)}",
            })
    return {"count": len(items), "items": items}


# --- evidence helpers for the ATT&CK rules (per-technique provenance pull) ---
def _lolbin_ev(ev: Evidence, *ids: str) -> list[str]:
    return [f"{i['provenance']} [{i['label']}]" for i in detect_lolbins(ev)["items"]
            if any(t in ids for t in i["techniques"])]


def _intent_ev(ev: Evidence, *ids: str) -> list[str]:
    return [i["provenance"] for i in analyze_command_intent(ev)["items"]
            if any(t in ids for t in i["techniques"])]


def _lineage_ev(ev: Evidence, *ids: str) -> list[str]:
    return [f"{i['provenance']} — {i['reason']}" for i in detect_lineage_anomalies(ev)["items"]
            if any(t in ids for t in i["techniques"])]


def _antiforensic_ev(ev: Evidence, *ids: str) -> list[str]:
    return [f"{i['provenance']} [{i['label']}]" for i in detect_antiforensics(ev)["items"]
            if any(t in ids for t in i["techniques"])]


def _timestomp_ev(ev: Evidence) -> list[str]:
    return [i["provenance"] for i in detect_timestomping(ev)["items"]]


def _deleted_dropper_ev(ev: Evidence) -> list[str]:
    out = []
    for r in ev.filesystem:
        if r.get("deleted") and _is_suspicious_path(r.get("path", "")):
            out.append(f"{ev.host} [$MFT]: deleted record {r.get('path','')} "
                       f"(InUse=false, created {r.get('created','')})")
    return out


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


def _wmi_evidence(ev: Evidence) -> list[str]:
    out = []
    for w in ev.wmi:
        out.append(f"{w.get('filter_name','?')} -> {w.get('consumer_name','?')} "
                   f"({w.get('consumer_type','?')}): {w.get('command') or w.get('query','')}".strip())
    return out


def _ingress_evidence(ev: Evidence) -> list[str]:
    bh = browser_history(ev)
    out = [f"{d.get('browser') or 'browser'} downloaded {d.get('url','')} -> {d.get('target_path','')}".strip()
           for d in bh["executable_downloads"]]
    # LOLBin and decoded-cradle downloads are ingress too (certutil/bitsadmin/IWR/...)
    out += _lolbin_ev(ev, "T1105") + _intent_ev(ev, "T1105")
    return out


def _user_execution_evidence(ev: Evidence) -> list[str]:
    """A binary in a user-writable path with execution evidence (prefetch/shimcache)."""
    out = []
    for p in ev.prefetch:
        if _is_suspicious_path(p.get("path", "")):
            out.append(f"prefetch: {p.get('name','')} ran {p.get('run_count','?')}x, "
                       f"last {p.get('last_run','')} ({p.get('path','')})")
    for s in ev.shimcache:
        if _is_suspicious_path(s.get("path", "")) and s.get("executed"):
            out.append(f"shimcache: {s.get('path','')} (present + executed)")
    return out


# Each rule: technique id/name, the tactics it serves, and a matcher returning
# the concrete evidence rows that support it. A technique is "detected" only if
# its matcher finds evidence — so every mapping is traceable, never asserted.
ATTACK_RULES = [
    {"id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell",
     "tactics": ["Execution"],
     "match": lambda ev: [_e(e) for e in ev.events if e["process"] == "powershell.exe"]
                         + [f"{p.get('name','')} {p.get('cmdline','')}".strip()
                            for p in ev.processes if (p.get("name") or "").lower() == "powershell.exe"]},
    {"id": "T1547.001", "name": "Boot or Logon Autostart: Registry Run Keys",
     "tactics": ["Persistence", "Privilege Escalation"],
     "match": lambda ev: [_r(r) for r in ev.registry if r["category"] == "run"
                          and any(p in (r.get("value_data") or "").lower() for p in SUSPICIOUS_PATHS)]},
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
                         + [_r(r) for r in ev.registry if "windefendsvc" in (r.get("key") or "").lower() and r.get("value_name") == "ImagePath"]
                         + [f"{p.get('name','')} {p.get('path','')}".strip() for p in ev.processes
                            if p.get("path") and any(s in p["path"].lower() for s in SUSPICIOUS_PATHS)]},
    {"id": "T1218.011", "name": "System Binary Proxy Execution: Rundll32",
     "tactics": ["Defense Evasion"],
     "match": lambda ev: [_e(e) for e in ev.events if e["process"] == "rundll32.exe"]
                         + _lolbin_ev(ev, "T1218.011")},
    {"id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools",
     "tactics": ["Defense Evasion"],
     "match": lambda ev: [_r(r) for r in ev.registry if "defender" in (r.get("key") or "").lower() and "disable" in (r.get("value_name") or "").lower()]
                         + _intent_ev(ev, "T1562.001") + _antiforensic_ev(ev, "T1562.001")},
    {"id": "T1070.001", "name": "Indicator Removal: Clear Windows Event Logs",
     "tactics": ["Defense Evasion"],
     "match": lambda ev: [_e(e) for e in ev.events if e["event_id"] in ANTIFORENSIC_EVENT_IDS]
                         + _antiforensic_ev(ev, "T1070.001")},
    {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols",
     "tactics": ["Command and Control"],
     "match": lambda ev: [f"{c['via']} -> {c['endpoint']}" for c in corroborated_c2(ev)]},
    {"id": "T1052.001", "name": "Exfiltration Over Physical Medium: USB",
     "tactics": ["Exfiltration"],
     "match": lambda ev: [_r(r) for r in ev.registry if r["category"] == "usbstor" and r["value_name"] == "FriendlyName"]
                         + [_e(e) for e in ev.events if e["event_id"] == 6416]},
    {"id": "T1546.003", "name": "Event Triggered Execution: WMI Event Subscription",
     "tactics": ["Persistence", "Privilege Escalation"],
     "match": _wmi_evidence},
    {"id": "T1105", "name": "Ingress Tool Transfer",
     "tactics": ["Command and Control"],
     "match": _ingress_evidence},
    {"id": "T1204.002", "name": "User Execution: Malicious File",
     "tactics": ["Execution"],
     "match": _user_execution_evidence},

    # --- Detection Depth: LOLBin / fileless / lineage / anti-forensics ------
    {"id": "T1218", "name": "System Binary Proxy Execution",
     "tactics": ["Defense Evasion"],
     "match": lambda ev: _lolbin_ev(ev, "T1218") + _lineage_ev(ev, "T1218")},
    {"id": "T1218.002", "name": "System Binary Proxy Execution: Control Panel",
     "tactics": ["Defense Evasion"], "match": lambda ev: _lolbin_ev(ev, "T1218.002")},
    {"id": "T1218.003", "name": "System Binary Proxy Execution: CMSTP",
     "tactics": ["Defense Evasion"], "match": lambda ev: _lolbin_ev(ev, "T1218.003")},
    {"id": "T1218.004", "name": "System Binary Proxy Execution: InstallUtil",
     "tactics": ["Defense Evasion"], "match": lambda ev: _lolbin_ev(ev, "T1218.004")},
    {"id": "T1218.005", "name": "System Binary Proxy Execution: Mshta",
     "tactics": ["Defense Evasion"], "match": lambda ev: _lolbin_ev(ev, "T1218.005")},
    {"id": "T1218.007", "name": "System Binary Proxy Execution: Msiexec",
     "tactics": ["Defense Evasion"], "match": lambda ev: _lolbin_ev(ev, "T1218.007")},
    {"id": "T1218.009", "name": "System Binary Proxy Execution: Regsvcs/Regasm",
     "tactics": ["Defense Evasion"], "match": lambda ev: _lolbin_ev(ev, "T1218.009")},
    {"id": "T1218.010", "name": "System Binary Proxy Execution: Regsvr32",
     "tactics": ["Defense Evasion"], "match": lambda ev: _lolbin_ev(ev, "T1218.010")},
    {"id": "T1218.013", "name": "System Binary Proxy Execution: Mavinject",
     "tactics": ["Defense Evasion"], "match": lambda ev: _lolbin_ev(ev, "T1218.013")},
    {"id": "T1127.001", "name": "Trusted Developer Utilities Proxy Execution: MSBuild",
     "tactics": ["Defense Evasion"], "match": lambda ev: _lolbin_ev(ev, "T1127.001")},
    {"id": "T1047", "name": "Windows Management Instrumentation",
     "tactics": ["Execution"],
     "match": lambda ev: _lolbin_ev(ev, "T1047") + _lineage_ev(ev, "T1047")},
    {"id": "T1059.003", "name": "Command and Scripting Interpreter: Windows Command Shell",
     "tactics": ["Execution"], "match": lambda ev: _lineage_ev(ev, "T1059.003")},
    {"id": "T1505.003", "name": "Server Software Component: Web Shell",
     "tactics": ["Persistence"], "match": lambda ev: _lineage_ev(ev, "T1505.003")},
    {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment",
     "tactics": ["Initial Access"], "match": lambda ev: _lineage_ev(ev, "T1566.001")},
    {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory",
     "tactics": ["Credential Access"], "match": lambda ev: _lineage_ev(ev, "T1003.001")},
    {"id": "T1003", "name": "OS Credential Dumping",
     "tactics": ["Credential Access"], "match": lambda ev: _lolbin_ev(ev, "T1003")},
    {"id": "T1140", "name": "Deobfuscate/Decode Files or Information",
     "tactics": ["Defense Evasion"],
     "match": lambda ev: _lolbin_ev(ev, "T1140") + _intent_ev(ev, "T1140")},
    {"id": "T1027", "name": "Obfuscated Files or Information",
     "tactics": ["Defense Evasion"], "match": lambda ev: _intent_ev(ev, "T1027")},
    {"id": "T1055", "name": "Process Injection",
     "tactics": ["Defense Evasion", "Privilege Escalation"],
     "match": lambda ev: _intent_ev(ev, "T1055") + _lolbin_ev(ev, "T1055")},
    {"id": "T1490", "name": "Inhibit System Recovery",
     "tactics": ["Impact"], "match": lambda ev: _antiforensic_ev(ev, "T1490")},
    {"id": "T1070", "name": "Indicator Removal",
     "tactics": ["Defense Evasion"], "match": lambda ev: _antiforensic_ev(ev, "T1070")},
    {"id": "T1070.004", "name": "Indicator Removal: File Deletion",
     "tactics": ["Defense Evasion"],
     "match": lambda ev: _antiforensic_ev(ev, "T1070.004") + _deleted_dropper_ev(ev)},
    {"id": "T1070.006", "name": "Indicator Removal: Timestomp",
     "tactics": ["Defense Evasion"], "match": _timestomp_ev},
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
    "prefetch_execution": (prefetch_execution, {}),
    "shimcache_entries": (shimcache_entries, {}),
    "filesystem_timeline": (filesystem_timeline, {
        "around": {"type": "string", "description": "ISO timestamp to center on"},
        "minutes": {"type": "integer", "description": "window half-width in minutes"},
        "suspicious_only": {"type": "boolean", "description": "only files in user-writable paths"}}),
    "browser_history": (browser_history, {"downloads_only": {"type": "boolean"}}),
    "wmi_persistence": (wmi_persistence, {}),
    "detect_lolbins": (detect_lolbins, {}),
    "analyze_command_intent": (analyze_command_intent, {}),
    "detect_lineage_anomalies": (detect_lineage_anomalies, {}),
    "detect_timestomping": (detect_timestomping, {}),
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
