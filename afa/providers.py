"""Investigation providers.

Three ways to drive the same forensic tool belt:

* OfflinePlanner — a deterministic, dependency-free planner. It maps a question
  to tool calls with keyword intent and composes a grounded answer from the
  results. No model, no network — so the repo runs and demos with zero setup,
  and the answers are still 100% traceable to tool output.

* LocalOllamaProvider — the intended production mode. It hands the tools to a
  local model via Ollama's tool-calling API on localhost and runs the agent
  loop. Evidence never leaves the host.

* CloudProvider — optional, and refused unless egress is explicitly enabled.
"""

from __future__ import annotations

import json
import re

from .egress import EGRESS_WARNING, assert_local, egress_allowed
from .loader import Evidence
from .models import Answer, ToolCall
from .tools import dispatch, tool_specs

SYSTEM = (
    "You are a digital-forensics analyst working an incident on a single Windows host. "
    "You may ONLY answer using the provided tools, which parse the evidence. Never invent "
    "facts. Call tools to gather what you need, then give a concise answer that cites what "
    "the tools returned. If the tools do not support a conclusion, say so."
)


# --------------------------------------------------------------------------
# Offline deterministic planner
# --------------------------------------------------------------------------
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
FILE_RE = re.compile(r"\b[\w.-]+\.(?:exe|dll|ps1|bat|dit)\b", re.I)


class OfflinePlanner:
    name = "offline-planner"

    def investigate(self, question: str, ev: Evidence) -> Answer:
        plan = self._plan(question, ev)
        calls = [ToolCall(name=n, args=a, result=dispatch(n, a, ev)) for n, a in plan]
        return Answer(question=question, text=self._compose(question, calls),
                      provider=self.name, tool_calls=calls)

    def narrate(self, ev: Evidence) -> str:
        """Deterministic executive brief assembled from the findings (no model)."""
        from .brief import build_brief, render_brief
        return render_brief(build_brief(ev))

    def _plan(self, q: str, ev: Evidence) -> list[tuple[str, dict]]:
        ql = q.lower().replace("-", " ")
        # explicit indicator lookups win
        ip = IP_RE.search(q)
        if ip and ("evidence" in ql or "indicator" in ql or "connect" in ql or "ip" in ql or "c2" in ql):
            return [("find_indicator", {"value": ip.group(0)})]
        fm = FILE_RE.search(q)
        if fm and ("evidence" in ql or "indicator" in ql or "file" in ql or "ran" in ql):
            return [("find_indicator", {"value": fm.group(0)})]

        if any(w in ql for w in ("mitre", "att&ck", "technique", "ttp", "tactic", "kill chain")):
            return [("map_attack", {})]
        if any(w in ql for w in ("wmi", "subscription", "event consumer", "event filter", "consumerbinding")):
            return [("wmi_persistence", {})]
        if any(w in ql for w in ("process tree", "process chain", "parent process", "spawn", "what spawned")):
            return [("process_tree", {})]
        if any(w in ql for w in ("scheduled task", "schtask", "scheduled")):
            return [("scheduled_tasks", {})]
        if any(w in ql for w in ("account", "new user", "user creat")):
            return [("account_changes", {})]
        if any(w in ql for w in ("persist", "autorun", "run key", "startup", "stay", "reboot", "service")):
            return [("list_autoruns", {})]
        if any(w in ql for w in ("usb", "removable", "thumb", "external device", "exfil")):
            return [("usb_history", {})]
        if any(w in ql for w in ("cover", "anti forensic", "antiforensic", "clear", "wipe", "tamper", "track")):
            return [("detect_antiforensics", {})]
        if any(w in ql for w in ("scriptblock", "script block", "4104", "decoded", "powershell command")):
            return [("powershell_activity", {})]
        if any(w in ql for w in ("prefetch", "run count", "how many times", "times executed")):
            if ev.prefetch:
                return [("prefetch_execution", {})]
        if any(w in ql for w in ("shimcache", "appcompat", "amcache present")):
            if ev.shimcache:
                return [("shimcache_entries", {})]
        if any(w in ql for w in ("mft", "file system", "filesystem", "first write", "first written",
                                 "dropped", "when was", "written to disk", "file timeline")):
            if ev.filesystem:
                return [("filesystem_timeline", {})]
        if any(w in ql for w in ("browser", "download", "chrome", "edge", "firefox", "drive by",
                                 "drive-by", "url visited", "downloaded")):
            if ev.browser:
                return [("browser_history", {})]
        if any(w in ql for w in ("amcache", "shimcache", "program execution", "what ran", "programs")):
            if ev.shimcache:
                return [("shimcache_entries", {})]
            if ev.programs:
                return [("program_execution", {})]
        if any(w in ql for w in ("c2", "command and control", "beacon", "outbound", "network", "connect", "external")):
            # prefer live network artifacts when the host was triaged live
            if ev.network:
                return [("network_connections", {"external_only": True})]
            return [("search_events", {"contains": "203.0.113"})]
        if any(w in ql for w in ("timeline", "sequence", "order", "what happened", "chronolog")):
            return [("timeline", {})]
        if any(w in ql for w in ("process", "executed", "powershell", "malware", "suspicious", "ran")):
            # use live process list if there are no process-creation events
            if not any(e.get("event_id") == 4688 for e in ev.events) and ev.processes:
                return [("running_processes", {})]
            return [("search_events", {"event_id": 4688})]
        # default triage sweep
        return [("list_autoruns", {}), ("search_events", {"event_id": 4688}),
                ("detect_antiforensics", {})]

    def _compose(self, q: str, calls: list[ToolCall]) -> str:
        parts: list[str] = []
        for c in calls:
            r = c.result
            if c.name == "list_autoruns":
                susp = r.get("suspicious", [])
                if susp:
                    lines = "; ".join(f"{s['value']} -> {s['data']}" for s in susp)
                    parts.append(f"Persistence: {r['suspicious_count']} suspicious autorun(s) of "
                                 f"{r['count']} total. Notable: {lines}.")
                else:
                    parts.append(f"Persistence: {r['count']} autorun entries, none obviously malicious.")
            elif c.name == "usb_history":
                if r["count"]:
                    names = "; ".join(i["value_data"] for i in r["items"] if i["value_name"] == "FriendlyName")
                    parts.append(f"Removable storage: {r['count']} USBSTOR record(s). Device(s): {names or 'see registry'}.")
                else:
                    parts.append("Removable storage: no USBSTOR records found.")
            elif c.name == "detect_antiforensics":
                if r["count"]:
                    when = "; ".join(f"{i['ts']} (event {i['event_id']})" for i in r["items"])
                    parts.append(f"Anti-forensics: yes — {when}. {r['note']}")
                else:
                    parts.append("Anti-forensics: no log-clearing events found.")
            elif c.name == "search_events":
                items = r["items"][:6]
                if items:
                    lines = "; ".join(
                        f"{i['ts']} {i['process'] or 'event ' + str(i['event_id'])}"
                        f"{(' ' + i['cmdline']) if i.get('cmdline') else ''}"
                        f"{(' [' + i['detail'] + ']') if i.get('detail') else ''}"
                        for i in items
                    )
                    parts.append(f"Matching events ({r['count']}): {lines}.")
                else:
                    parts.append("No matching events.")
            elif c.name == "timeline":
                lines = " -> ".join(f"{i['ts'][11:16]} {i['process'] or 'evt' + str(i['event_id'])}"
                                    for i in r["items"])
                parts.append(f"Timeline ({r['count']} events): {lines}.")
            elif c.name == "find_indicator":
                parts.append(f"Indicator '{r['indicator']}': {r['registry_hits']} registry hit(s), "
                             f"{r['event_hits']} event hit(s).")
            elif c.name == "query_registry":
                parts.append(f"Registry '{r['pattern']}': {r['count']} match(es).")
            elif c.name == "map_attack":
                techs = "; ".join(f"{t['id']} {t['name']} ({'/'.join(t['tactics'])})" for t in r["techniques"])
                parts.append(f"Mapped {r['technique_count']} ATT&CK technique(s) across "
                             f"{r['tactics_covered']} tactic(s): {techs}.")
            elif c.name == "process_tree":
                parts.append(f"Process tree ({r['count']} creations):\n{r['tree']}")
            elif c.name == "scheduled_tasks":
                if r["count"]:
                    lines = "; ".join(i["detail"] for i in r["items"])
                    parts.append(f"Scheduled tasks ({r['count']}): {lines}.")
                else:
                    parts.append("Scheduled tasks: none found.")
            elif c.name == "account_changes":
                if r["count"]:
                    lines = "; ".join(f"{i['action']}: {i['detail']}" for i in r["items"])
                    parts.append(f"Account changes ({r['count']}): {lines}.")
                else:
                    parts.append("Account changes: none found.")
            elif c.name == "network_connections":
                if r["count"]:
                    lines = "; ".join(f"{i.get('process') or 'pid ' + str(i.get('pid'))} -> "
                                      f"{i.get('remote','')} ({i.get('state','')})" for i in r["items"][:6])
                    parts.append(f"External network connections ({r['count']}): {lines}.")
                else:
                    parts.append("No external network connections observed.")
            elif c.name == "running_processes":
                if r["count"]:
                    lines = "; ".join(f"{i.get('name','')} (pid {i.get('pid')})"
                                      f"{(' ' + i['cmdline']) if i.get('cmdline') else ''}"
                                      for i in r["items"][:6])
                    parts.append(f"Running processes ({r['count']}): {lines}.")
                else:
                    parts.append("No processes captured.")
            elif c.name == "local_users":
                names = ", ".join(f"{u['name']}{' (admin)' if 'Admin' in (u.get('groups') or '') else ''}"
                                  for u in r["items"])
                parts.append(f"Local users ({r['count']}): {names}.")
            elif c.name == "program_execution":
                lines = "; ".join(f"{i.get('name','')} ({i.get('sha1','')[:12]}…)" for i in r["items"][:6])
                parts.append(f"Program execution ({r['count']}): {lines}.")
            elif c.name == "powershell_activity":
                lines = "; ".join((i.get("detail") or i.get("cmdline") or "")[:90] for i in r["items"][:5])
                parts.append(f"PowerShell activity ({r['count']}): {lines}.")
            elif c.name == "prefetch_execution":
                if r["count"]:
                    lines = "; ".join(f"{i.get('name','')} ({i.get('run_count','?')}x, last {i.get('last_run','')})"
                                      for i in r["items"][:6])
                    extra = f" — {r['suspicious_count']} in user-writable paths" if r["suspicious_count"] else ""
                    parts.append(f"Prefetch execution ({r['count']}{extra}): {lines}.")
                else:
                    parts.append("Prefetch: no execution evidence collected.")
            elif c.name == "shimcache_entries":
                if r["count"]:
                    lines = "; ".join(f"{i.get('path','')}{' (executed)' if i.get('executed') else ''}"
                                      for i in r["items"][:6])
                    extra = f" — {r['suspicious_count']} in user-writable paths" if r["suspicious_count"] else ""
                    parts.append(f"Shimcache/Amcache ({r['count']}{extra}): {lines}.")
                else:
                    parts.append("Shimcache/Amcache: no entries collected.")
            elif c.name == "filesystem_timeline":
                drop = r.get("earliest_drop")
                head = (f"Earliest suspicious file write: {drop.get('path','')} at {drop.get('created','')}. "
                        if drop else "")
                lines = "; ".join(f"{i.get('created','')} {i.get('path','')}" for i in r["items"][:6])
                parts.append(f"{head}File-system timeline ({r['count']}): {lines}.")
            elif c.name == "browser_history":
                if r["download_count"]:
                    dls = "; ".join(f"{d.get('url','')} -> {d.get('target_path','')}"
                                    for d in r["executable_downloads"][:4]) or \
                          "; ".join(d.get("url", "") for d in r["downloads"][:4])
                    parts.append(f"Browser: {r['download_count']} download(s), "
                                 f"{len(r['executable_downloads'])} executable. {dls}.")
                else:
                    parts.append(f"Browser history ({r['count']} record(s)): no downloads observed.")
            elif c.name == "wmi_persistence":
                if r["count"]:
                    lines = "; ".join(f"{w.get('filter_name','?')} -> {w.get('consumer_name','?')} "
                                      f"({w.get('command') or w.get('query','')})" for w in r["items"][:4])
                    parts.append(f"WMI persistence ({r['count']}, {r['command_consumers']} command-line): {lines}.")
                else:
                    parts.append("WMI persistence: no event subscriptions found.")
        return " ".join(parts) if parts else "No tools produced a result."


# --------------------------------------------------------------------------
# Transport-agnostic agent loop (shared; unit-testable with a fake `chat`)
# --------------------------------------------------------------------------
def run_agent_loop(chat, question: str, ev: Evidence, provider_name: str, max_steps: int = 6) -> Answer:
    """Drive a tool-calling investigation.

    `chat(messages, tools) -> assistant_message_dict` is the only model contact.
    The loop dispatches every tool the model requests, threads the results back,
    and returns a grounded Answer. Injecting a scripted `chat` lets the loop be
    verified end-to-end without a live model.
    """
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": question}]
    trace: list[ToolCall] = []
    for _ in range(max_steps):
        msg = chat(messages, tool_specs())
        calls = msg.get("tool_calls") or []
        if not calls:
            return Answer(question=question, text=(msg.get("content") or "").strip(),
                          provider=provider_name, tool_calls=trace)
        messages.append(msg)
        for call in calls:
            fn = call.get("function", {})
            name = fn.get("name", "")
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            result = dispatch(name, args, ev)
            trace.append(ToolCall(name=name, args=args, result=result))
            messages.append({"role": "tool", "content": json.dumps(result)[:4000]})
    return Answer(question=question, text="Reached step limit before a final answer.",
                  provider=provider_name, tool_calls=trace)


# --------------------------------------------------------------------------
# Local Ollama provider (tool-calling agent loop)
# --------------------------------------------------------------------------
class LocalOllamaProvider:
    def __init__(self, model: str = "llama3.1", host: str = "http://localhost:11434", max_steps: int = 6):
        self.model = model
        self.host = host.rstrip("/")
        self.max_steps = max_steps
        self.name = f"ollama:{model}"
        assert_local(self.host)  # localhost only; never trips egress

    def _chat(self, messages, tools):
        import requests  # local-only HTTP; lazy import keeps offline mode dep-free
        resp = requests.post(
            f"{self.host}/api/chat",
            json={"model": self.model, "messages": messages, "tools": tools, "stream": False},
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json().get("message", {})

    def investigate(self, question: str, ev: Evidence) -> Answer:
        return run_agent_loop(self._chat, question, ev, self.name, self.max_steps)

    def narrate(self, ev: Evidence) -> str:
        """Have the local model write an incident narrative grounded in the brief."""
        from .brief import build_brief
        brief = build_brief(ev)
        prompt = (
            "Write a tight executive incident summary (under 180 words) from these grounded "
            "findings. Do not add facts beyond them. Findings JSON:\n" + json.dumps(brief)
        )
        msg = self._chat(
            [{"role": "system", "content": "You are an incident-response lead briefing leadership."},
             {"role": "user", "content": prompt}],
            [],  # no tools for the narrative pass
        )
        return (msg.get("content") or "").strip()


# --------------------------------------------------------------------------
# Optional cloud provider (refused unless egress is explicitly allowed)
# --------------------------------------------------------------------------
class CloudProvider:
    def __init__(self, model: str = "claude-opus-4-8", api_key: str | None = None):
        import os
        self.url = "https://api.anthropic.com/v1/messages"
        assert_local(self.url)  # raises EgressBlocked unless AFA_ALLOW_EGRESS is set
        self.model = model
        self.name = f"cloud:{model}"
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        print(EGRESS_WARNING)

    def investigate(self, question: str, ev: Evidence) -> Answer:
        import requests

        # A single grounded pass: run the offline plan's tools, hand the results to
        # the model to phrase, and mark the answer as having used egress.
        base = OfflinePlanner().investigate(question, ev)
        context = json.dumps([{"tool": c.name, "result": c.result} for c in base.tool_calls])[:6000]
        resp = requests.post(
            self.url,
            headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={"model": self.model, "max_tokens": 400, "system": SYSTEM,
                  "messages": [{"role": "user",
                                "content": f"Question: {question}\nTool results: {context}"}]},
            timeout=60,
        )
        resp.raise_for_status()
        text = "".join(b.get("text", "") for b in resp.json().get("content", [])
                       if b.get("type") == "text").strip()
        return Answer(question=question, text=text, provider=self.name,
                      tool_calls=base.tool_calls, egress_used=True)


def get_provider(mode: str, model: str | None = None):
    if mode == "offline":
        return OfflinePlanner()
    if mode == "local":
        return LocalOllamaProvider(model=model or "llama3.1")
    if mode == "cloud":
        return CloudProvider(model=model or "claude-opus-4-8")
    raise ValueError(f"unknown mode: {mode}")
