"""A local web GUI for the air-gapped forensic analyst.

Runs entirely on the analyst's box: FastAPI binds to 127.0.0.1, serves a
single-page app, and exposes the same deterministic engine over JSON. No egress,
no build step, no external assets — consistent with the air-gap posture. Launch
with `afa gui --package <pkg>` (or against the bundled sample with no arguments).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from .brief import build_brief, render_brief
from .loader import load_evidence
from .package import load_package, verify_package
from .rootcause import build_reconstruction
from .tools import (browser_history, filesystem_timeline, list_autoruns, map_attack,
                    prefetch_execution, scheduled_tasks, shimcache_entries, timeline,
                    wmi_persistence)

STATIC = Path(__file__).parent / "static"


def create_app(source: dict | None = None):
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse

    source = source or {}
    app = FastAPI(title="Air-Gapped Forensic Analyst", docs_url=None, redoc_url=None)

    @lru_cache(maxsize=1)
    def _evidence():
        if source.get("package"):
            ev, manifest = load_package(source["package"])
            custody = verify_package(source["package"])
            return ev, manifest, {"ok": custody["ok"], "files": custody["files"]}
        ev = load_evidence(source.get("dir"), events_path=source.get("events"),
                           registry_path=source.get("registry"),
                           prefetch_path=source.get("prefetch"), shimcache_path=source.get("shimcache"),
                           mft_path=source.get("mft"), browser_path=source.get("browser"),
                           wmi_path=source.get("wmi"))
        return ev, None, None

    @lru_cache(maxsize=1)
    def _case_payload():
        ev, manifest, custody = _evidence()
        recon = build_reconstruction(ev)
        attack = map_attack(ev)
        autoruns = list_autoruns(ev)
        return {
            "host": ev.host,
            "manifest": manifest,
            "custody": custody,
            "summary": render_brief(build_brief(ev)),
            "rootcause": recon,
            "attack": attack,
            "counts": {
                "events": len(ev.events), "registry": len(ev.registry),
                "processes": len(ev.processes), "network": len(ev.network),
                "users": len(ev.users), "programs": len(ev.programs),
                "prefetch": len(ev.prefetch), "shimcache": len(ev.shimcache),
                "filesystem": len(ev.filesystem), "browser": len(ev.browser),
                "wmi": len(ev.wmi),
            },
            "artifacts": {
                "processes": ev.processes,
                "network": ev.network,
                "users": ev.users,
                "programs": ev.programs,
                "services": ev.services,
                "persistence": autoruns["items"],
                "tasks": scheduled_tasks(ev)["items"],
                "events": timeline(ev)["items"],
                "prefetch": prefetch_execution(ev)["items"],
                "shimcache": shimcache_entries(ev)["items"],
                "filesystem": filesystem_timeline(ev)["items"],
                "browser": browser_history(ev)["items"],
                "wmi": wmi_persistence(ev)["items"],
            },
        }

    @app.get("/", response_class=HTMLResponse)
    def index():
        return (STATIC / "index.html").read_text()

    @app.get("/api/case")
    def case():
        return _case_payload()

    @app.post("/api/ask")
    def ask(payload: dict):
        from .providers import get_provider
        ev, _, _ = _evidence()
        provider = get_provider(source.get("mode", "offline"), source.get("model"))
        ans = provider.investigate(payload.get("question", ""), ev)
        return {"text": ans.text, "grounded": ans.grounded,
                "tool_calls": [{"name": c.name, "args": c.args} for c in ans.tool_calls]}

    return app


def serve(source: dict | None = None, host: str = "127.0.0.1", port: int = 8420):
    import uvicorn
    uvicorn.run(create_app(source), host=host, port=port, log_level="warning")
