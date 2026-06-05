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
        assert "explorer.exe" in self.recon["root_cause"]
        assert "phishing" in self.recon["root_cause"].lower()
        assert self.recon["root_cause_confidence"] == "medium"  # inferred vector, no email/proxy logs

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
        assert io["file_hashes"]                       # hashes from programs.json
        assert "supportadmin" in io["accounts"]
        assert any("Public" in p for p in io["suspicious_paths"])

    def test_states_gaps_and_pivots_honestly(self):
        assert any("inferred" in g.lower() for g in self.recon["gaps"])
        assert any("$MFT" in g for g in self.recon["gaps"])
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
        assert r["rootcause"]["root_cause_confidence"] == "medium"
        assert r["counts"]["processes"] == 4 and r["counts"]["programs"] == 2

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
