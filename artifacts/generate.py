"""Generate synthetic forensic artifacts for a single compromised Windows host.

Story: WIN-FIN-07 is compromised via a PowerShell downloader. The attacker
establishes Run-key + malicious-service persistence, beacons to a C2 host,
plugs in a USB device, and clears the Security event log to cover tracks.

Everything here is synthetic. All addresses are RFC 5737 documentation ranges.
This file is safe to commit and contains no real host or personal data.

Run:  python artifacts/generate.py
"""

import json
from pathlib import Path

HOST = "WIN-FIN-07"
C2 = "203.0.113.45"
HERE = Path(__file__).resolve().parent

# --------------------------------------------------------------------------
# Registry export (structured)
# --------------------------------------------------------------------------
REGISTRY = [
    # --- legitimate noise ---
    {"hive": "HKCU", "key": r"Software\Microsoft\Windows\CurrentVersion\Run",
     "value_name": "OneDrive", "value_data": r"C:\Program Files\Microsoft OneDrive\OneDrive.exe /background",
     "last_write": "2026-01-03T08:00:00Z", "category": "run"},
    {"hive": "HKLM", "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
     "value_name": "SecurityHealth", "value_data": r"%windir%\system32\SecurityHealthSystray.exe",
     "last_write": "2025-11-20T00:00:00Z", "category": "run"},
    # --- attacker persistence: masqueraded Run key ---
    {"hive": "HKLM", "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
     "value_name": "Updater", "value_data": r"C:\Users\Public\svchost.exe",
     "last_write": "2026-04-14T09:31:00Z", "category": "run"},
    # --- attacker persistence: malicious service ---
    {"hive": "HKLM", "key": r"SYSTEM\CurrentControlSet\Services\WinDefendSvc",
     "value_name": "ImagePath", "value_data": r"C:\Windows\Temp\wds.exe -enc SQBFAFgA",
     "last_write": "2026-04-14T09:33:00Z", "category": "service"},
    {"hive": "HKLM", "key": r"SYSTEM\CurrentControlSet\Services\WinDefendSvc",
     "value_name": "Start", "value_data": "2",
     "last_write": "2026-04-14T09:33:00Z", "category": "service"},
    # --- USB device insertion ---
    {"hive": "HKLM", "key": r"SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade",
     "value_name": "FriendlyName", "value_data": "SanDisk Cruzer Blade USB Device",
     "last_write": "2026-04-14T09:40:00Z", "category": "usbstor"},
    {"hive": "HKLM", "key": r"SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade",
     "value_name": "SerialNumber", "value_data": "4C530001120607116523",
     "last_write": "2026-04-14T09:40:00Z", "category": "usbstor"},
    # --- recent docs noise ---
    {"hive": "HKCU", "key": r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
     "value_name": "0", "value_data": "Q1-budget.xlsx",
     "last_write": "2026-04-14T08:50:00Z", "category": "other"},
    # --- defense tampering: disable Microsoft Defender ---
    {"hive": "HKLM", "key": r"SOFTWARE\Policies\Microsoft\Windows Defender",
     "value_name": "DisableAntiSpyware", "value_data": "1",
     "last_write": "2026-04-14T09:34:00Z", "category": "other"},
]

# --------------------------------------------------------------------------
# Windows event log (one record per line)
# --------------------------------------------------------------------------
def e(ts, event_id, channel, user, process, parent, cmdline="", dst_ip="", detail=""):
    return {
        "ts": ts, "event_id": event_id, "channel": channel, "computer": HOST,
        "user": user, "process": process, "parent_process": parent,
        "cmdline": cmdline, "dst_ip": dst_ip, "detail": detail,
    }

EVENTS = [
    e("2026-04-14T08:15:00Z", 4624, "Security", "WIN-FIN-07\\jdoe", "", "", detail="interactive logon"),
    e("2026-04-14T08:52:00Z", 4688, "Security", "WIN-FIN-07\\jdoe", "chrome.exe", "explorer.exe", "chrome.exe", detail="browser"),
    # initial execution
    e("2026-04-14T09:30:00Z", 4688, "Security", "WIN-FIN-07\\jdoe", "powershell.exe", "explorer.exe",
      "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", detail="encoded command"),
    # dropped payload + persistence
    e("2026-04-14T09:31:00Z", 4688, "Security", "WIN-FIN-07\\jdoe", "svchost.exe", "powershell.exe",
      r"C:\Users\Public\svchost.exe", detail="masqueraded binary in user-writable path"),
    e("2026-04-14T09:33:00Z", 7045, "System", "WIN-FIN-07\\SYSTEM", "services.exe", "",
      "WinDefendSvc", detail="A new service was installed: WinDefendSvc"),
    # C2 beacon
    e("2026-04-14T09:35:00Z", 3, "Sysmon", "WIN-FIN-07\\jdoe", "svchost.exe", "powershell.exe",
      "", dst_ip=C2, detail="outbound TLS to 203.0.113.45:443"),
    e("2026-04-14T09:36:00Z", 4688, "Security", "WIN-FIN-07\\jdoe", "rundll32.exe", "svchost.exe",
      "rundll32.exe C:\\Users\\Public\\d.dll,Run", detail="proxied execution"),
    # scheduled-task persistence
    e("2026-04-14T09:37:00Z", 4698, "Security", "WIN-FIN-07\\SYSTEM", "svchost.exe", "",
      "\\UpdateCheck", detail="A scheduled task was created: \\UpdateCheck -> C:\\Users\\Public\\svchost.exe"),
    # local account creation
    e("2026-04-14T09:38:00Z", 4720, "Security", "WIN-FIN-07\\SYSTEM", "", "",
      "supportadmin", detail="A user account was created: supportadmin"),
    # USB
    e("2026-04-14T09:40:00Z", 6416, "Security", "WIN-FIN-07\\jdoe", "", "",
      "USBSTOR\\SanDisk_Cruzer_Blade", detail="external device recognized"),
    # anti-forensics
    e("2026-04-14T09:45:00Z", 1102, "Security", "WIN-FIN-07\\jdoe", "", "",
      "", detail="The audit log was cleared"),
    e("2026-04-14T09:46:00Z", 4634, "Security", "WIN-FIN-07\\jdoe", "", "", detail="logoff"),
]


def main():
    (HERE / "registry.json").write_text(json.dumps(REGISTRY, indent=2))
    with (HERE / "events.jsonl").open("w") as f:
        for ev in EVENTS:
            f.write(json.dumps(ev) + "\n")
    print(f"wrote {len(REGISTRY)} registry rows -> registry.json")
    print(f"wrote {len(EVENTS)} events -> events.jsonl")


if __name__ == "__main__":
    main()
