"""Ingest real evidence.

The bundled artifacts use a tidy internal schema, but real analysts arrive with
whatever their tooling produced. This module normalizes the formats people
actually have on hand into that internal schema, so the tools and the agent work
on real exports — not just the sample case.

Events:
  * native JSONL / JSON (our schema)
  * `Get-WinEvent ... | ConvertTo-Json` output (the no-extra-tools default)
  * CSV with flexible column names (Sysmon/SIEM exports)

Registry:
  * native registry.json (our schema)
  * `.reg` text exports (regedit / `reg export`)
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path

# ---- internal event schema keys ----
EVENT_KEYS = ("ts", "event_id", "channel", "computer", "user",
              "process", "parent_process", "cmdline", "dst_ip", "detail")


# --------------------------------------------------------------------------
# timestamps
# --------------------------------------------------------------------------
_WCF_DATE = re.compile(r"/Date\((\d+)(?:[+-]\d+)?\)/")  # PowerShell ConvertTo-Json date


def parse_ts(value) -> str:
    """Normalize a timestamp from several shapes into ISO-8601 UTC (…Z)."""
    if value is None or value == "":
        return ""
    if isinstance(value, (int, float)):
        # epoch seconds vs milliseconds
        secs = value / 1000 if value > 1e12 else value
        return datetime.fromtimestamp(secs, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    s = str(value).strip()
    m = _WCF_DATE.search(s)
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return s  # leave as-is; better to keep than to drop


# --------------------------------------------------------------------------
# Get-WinEvent JSON
# --------------------------------------------------------------------------
def _from_message(msg: str, field: str) -> str:
    m = re.search(rf"{re.escape(field)}:\s*([^\r\n]+)", msg or "")
    return m.group(1).strip() if m else ""


def _basename(p: str) -> str:
    """Last path component, splitting on either separator (Windows paths on Linux)."""
    return re.split(r"[\\/]", p.strip())[-1] if p else p


def _norm_winevent(obj: dict) -> dict:
    msg = obj.get("Message") or obj.get("message") or ""
    eid = obj.get("Id", obj.get("EventID", obj.get("event_id", 0)))
    proc = _basename(_from_message(msg, "New Process Name"))
    parent = _basename(_from_message(msg, "Creator Process Name"))
    return {
        "ts": parse_ts(obj.get("TimeCreated") or obj.get("ts")),
        "event_id": int(eid) if str(eid).isdigit() else 0,
        "channel": obj.get("LogName") or obj.get("channel") or "",
        "computer": obj.get("MachineName") or obj.get("computer") or "",
        "user": _from_message(msg, "Account Name") or obj.get("user", ""),
        "process": proc,
        "parent_process": parent,
        "cmdline": _from_message(msg, "Process Command Line"),
        "dst_ip": "",
        "detail": (msg.splitlines()[0].strip() if msg else ""),
    }


# --------------------------------------------------------------------------
# CSV (flexible columns)
# --------------------------------------------------------------------------
_CSV_ALIASES = {
    "ts": ("ts", "timecreated", "time", "timestamp", "date"),
    "event_id": ("event_id", "eventid", "event id", "id"),
    "channel": ("channel", "logname", "log"),
    "computer": ("computer", "machinename", "host", "hostname"),
    "user": ("user", "username", "account", "accountname"),
    "process": ("process", "newprocessname", "image", "processname"),
    "parent_process": ("parent_process", "parentprocessname", "parentimage", "parent"),
    "cmdline": ("cmdline", "commandline", "command"),
    "dst_ip": ("dst_ip", "destinationip", "remoteaddress", "destip"),
    "detail": ("detail", "message", "description", "info"),
}


def _norm_csv_row(row: dict) -> dict:
    lower = {k.lower().strip(): v for k, v in row.items() if k}
    out = {}
    for key, aliases in _CSV_ALIASES.items():
        val = next((lower[a] for a in aliases if a in lower and lower[a] not in (None, "")), "")
        out[key] = val
    out["ts"] = parse_ts(out["ts"])
    out["event_id"] = int(out["event_id"]) if str(out["event_id"]).isdigit() else 0
    if out["process"]:
        out["process"] = _basename(out["process"])
    if out["parent_process"]:
        out["parent_process"] = _basename(out["parent_process"])
    return out


# --------------------------------------------------------------------------
# .reg text export
# --------------------------------------------------------------------------
_HIVE_MAP = {
    "HKEY_LOCAL_MACHINE": "HKLM", "HKLM": "HKLM",
    "HKEY_CURRENT_USER": "HKCU", "HKCU": "HKCU",
    "HKEY_USERS": "HKU", "HKEY_CLASSES_ROOT": "HKCR",
}


def _categorize(key: str) -> str:
    k = key.lower()
    if k.endswith("\\run") or "\\run\\" in k:
        return "run"
    if "\\services\\" in k:
        return "service"
    if "usbstor" in k:
        return "usbstor"
    return "other"


def _unescape_reg(s: str) -> str:
    return s.replace('\\\\', '\\').replace('\\"', '"')


def normalize_reg(text: str) -> list[dict]:
    rows: list[dict] = []
    hive, key = "", ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("windows registry editor"):
            continue
        if line.startswith("[") and line.endswith("]"):
            full = line[1:-1]
            root, _, rest = full.partition("\\")
            hive = _HIVE_MAP.get(root.upper(), root)
            key = rest
            continue
        if "=" not in line:
            continue
        name_part, _, val_part = line.partition("=")
        name = "(Default)" if name_part.strip() == "@" else _unescape_reg(name_part.strip().strip('"'))
        val = val_part.strip()
        if val.startswith('"'):
            data = _unescape_reg(val.strip('"'))
        elif val.lower().startswith("dword:"):
            try:
                data = str(int(val.split(":", 1)[1], 16))
            except ValueError:
                data = val
        else:
            data = val
        rows.append({"hive": hive, "key": key, "value_name": name, "value_data": data,
                     "last_write": "", "category": _categorize(key)})
    return rows


# --------------------------------------------------------------------------
# dispatch by format
# --------------------------------------------------------------------------
def normalize_events(path: str | Path) -> list[dict]:
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".csv":
        return [_norm_csv_row(r) for r in csv.DictReader(io.StringIO(text))]
    if path.suffix.lower() == ".jsonl":
        objs = [json.loads(l) for l in text.splitlines() if l.strip()]
    else:  # .json — could be native list or Get-WinEvent array (or a single object)
        data = json.loads(text)
        objs = data if isinstance(data, list) else [data]
    # native rows already carry our keys; Get-WinEvent rows carry "Id"/"TimeCreated"
    out = []
    for o in objs:
        if "event_id" in o and "ts" in o:
            out.append({k: o.get(k, "") for k in EVENT_KEYS})
        else:
            out.append(_norm_winevent(o))
    return out


def normalize_registry(path: str | Path) -> list[dict]:
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".reg":
        return normalize_reg(text)
    data = json.loads(text)
    return data if isinstance(data, list) else [data]


# --------------------------------------------------------------------------
# deeper forensic sources — each is "one normalizer plus one tool"
#
# Every normalizer accepts (a) our native JSON/JSONL rows (pass-through) and
# (b) the export real analysts actually have on hand (Eric Zimmerman CSVs,
# BrowsingHistoryView, Autorunsc), auto-detected by column names. The aim is the
# same as the events/registry path: the tools work on real evidence, not just
# the sample.
# --------------------------------------------------------------------------
def _read_rows(path: str | Path) -> list[dict]:
    """Read .json (list or single obj), .jsonl, or .csv into a list of dicts."""
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig")
    suf = path.suffix.lower()
    if suf == ".csv":
        return [dict(r) for r in csv.DictReader(io.StringIO(text))]
    if suf == ".jsonl":
        return [json.loads(l) for l in text.splitlines() if l.strip()]
    data = json.loads(text)
    return data if isinstance(data, list) else [data]


def _pick(row: dict, aliases: tuple[str, ...], default=""):
    """First non-empty value among case-insensitive column aliases."""
    lower = {k.lower().strip(): v for k, v in row.items() if k}
    return next((lower[a] for a in aliases if a in lower and lower[a] not in (None, "")), default)


def _to_int(v, default=0) -> int:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def _suspicious_path(p: str) -> bool:
    pl = (p or "").lower()
    return any(s in pl for s in ("\\users\\public\\", "\\windows\\temp\\",
                                 "\\appdata\\local\\temp\\", "\\appdata\\roaming\\",
                                 "\\programdata\\", "\\downloads\\"))


def normalize_prefetch(path: str | Path) -> list[dict]:
    """Prefetch execution evidence. Accepts native JSON or PECmd (Zimmerman) CSV."""
    out = []
    for r in _read_rows(path):
        if "run_count" in r and "name" in r:  # native
            out.append({k: r.get(k, "") for k in
                        ("name", "path", "run_count", "last_run", "first_run", "prefetch_file")})
            out[-1]["run_count"] = _to_int(out[-1]["run_count"])
            continue
        exe = _pick(r, ("executablename", "name", "exename"))
        path_val = _pick(r, ("path", "fullpath", "filepath"))
        out.append({
            "name": _basename(exe) or exe,
            "path": path_val,
            "run_count": _to_int(_pick(r, ("runcount", "run_count", "timesexecuted"))),
            "last_run": parse_ts(_pick(r, ("lastrun", "last_run", "lastrun0", "lastexecuted"))),
            "first_run": parse_ts(_pick(r, ("firstrun", "first_run", "sourcecreated", "created"))),
            "prefetch_file": _pick(r, ("sourcefilename", "prefetch_file", "sourcefile")),
        })
    return out


def normalize_shimcache(path: str | Path) -> list[dict]:
    """Amcache/Shimcache (AppCompatCache) presence evidence. Native or Zimmerman CSV."""
    out = []
    for i, r in enumerate(_read_rows(path), 1):
        if "position" in r and ("path" in r or "name" in r):  # native
            row = {k: r.get(k, "") for k in ("position", "name", "path", "last_modified", "executed", "sha1")}
            row["position"] = _to_int(row["position"], i)
            row["executed"] = bool(row.get("executed"))
            out.append(row)
            continue
        path_val = _pick(r, ("path", "fullpath", "filepath", "applicationname"))
        executed = _pick(r, ("executed", "isexecuted", "execflag"))
        out.append({
            "position": _to_int(_pick(r, ("position", "cacheentryposition", "order")), i),
            "name": _basename(path_val) or _pick(r, ("name", "filename")),
            "path": path_val,
            "last_modified": parse_ts(_pick(r, ("lastmodifiedtimeutc", "last_modified",
                                                "lastmodified", "filekeylastwritetimestamp"))),
            "executed": str(executed).strip().lower() in ("true", "yes", "1", "executed"),
            "sha1": _pick(r, ("sha1", "sha1hash", "hash")),
        })
    return out


def normalize_mft(path: str | Path) -> list[dict]:
    """File-system timeline ($MFT). Native, MFTECmd CSV, or a generic file listing."""
    out = []
    for r in _read_rows(path):
        if "path" in r and ("created" in r or "modified" in r):  # native
            out.append({k: r.get(k, "") for k in
                        ("path", "name", "created", "modified", "mft_modified", "size", "is_directory")})
            out[-1]["size"] = _to_int(out[-1].get("size"), 0)
            out[-1]["is_directory"] = bool(out[-1].get("is_directory"))
            continue
        parent = _pick(r, ("parentpath", "parent_path"))
        fname = _pick(r, ("filename", "name", "file"))
        full = _pick(r, ("path", "fullpath"))
        if not full and (parent or fname):
            full = (parent.rstrip("\\") + "\\" + fname) if parent else fname
        out.append({
            "path": full,
            "name": _basename(full) or fname,
            "created": parse_ts(_pick(r, ("created0x10", "created", "creationtime", "sicreated"))),
            "modified": parse_ts(_pick(r, ("lastmodified0x10", "modified", "lastwritetime", "simodified"))),
            "mft_modified": parse_ts(_pick(r, ("lastrecordchange0x10", "mft_modified", "entrymodified"))),
            "size": _to_int(_pick(r, ("filesize", "size", "length"))),
            "is_directory": str(_pick(r, ("isdirectory", "is_directory"))).strip().lower() in ("true", "yes", "1"),
        })
    return out


def normalize_browser(path: str | Path) -> list[dict]:
    """Browser history + downloads. Native, or BrowsingHistoryView/Hindsight CSV."""
    out = []
    for r in _read_rows(path):
        if "url" in r and "type" in r:  # native
            out.append({k: r.get(k, "") for k in
                        ("type", "url", "title", "timestamp", "target_path", "browser")})
            continue
        url = _pick(r, ("url", "address"))
        target = _pick(r, ("target_path", "downloadpath", "savedfile", "filename", "fulltargetpath"))
        rtype = (_pick(r, ("type", "recordtype")) or ("download" if target else "visit")).lower()
        out.append({
            "type": "download" if "download" in rtype or target else "visit",
            "url": url,
            "title": _pick(r, ("title", "pagetitle")),
            "timestamp": parse_ts(_pick(r, ("timestamp", "visittime", "visiteddate",
                                            "starttime", "datetime", "lastvisiteddate"))),
            "target_path": target,
            "browser": _pick(r, ("browser", "source", "webbrowser")),
        })
    return out


def normalize_wmi(path: str | Path) -> list[dict]:
    """WMI event-subscription persistence. Native, or Autorunsc/wmi-dump CSV/JSON."""
    out = []
    for r in _read_rows(path):
        if "consumer_type" in r or ("filter_name" in r and "consumer_name" in r):  # native
            out.append({k: r.get(k, "") for k in
                        ("filter_name", "consumer_name", "consumer_type", "query", "command")})
            continue
        out.append({
            "filter_name": _pick(r, ("filter_name", "filter", "eventfilter", "name")),
            "consumer_name": _pick(r, ("consumer_name", "consumer", "eventconsumer")),
            "consumer_type": _pick(r, ("consumer_type", "consumerclass", "type")) or "CommandLineEventConsumer",
            "query": _pick(r, ("query", "queryexpression", "wql")),
            "command": _pick(r, ("command", "commandlinetemplate", "executablepath", "scripttext")),
        })
    return out
