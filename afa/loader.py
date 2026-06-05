"""Load forensic artifacts from disk into memory."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_DIR = Path(__file__).resolve().parent.parent / "artifacts"


@dataclass
class Evidence:
    """The whole case, in memory. Read-only as far as the tools are concerned."""

    registry: list[dict] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    processes: list[dict] = field(default_factory=list)
    network: list[dict] = field(default_factory=list)
    users: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    programs: list[dict] = field(default_factory=list)
    # deeper forensic sources (each is one normalizer + one tool)
    prefetch: list[dict] = field(default_factory=list)      # execution: run counts + times
    shimcache: list[dict] = field(default_factory=list)     # Amcache/Shimcache presence
    filesystem: list[dict] = field(default_factory=list)    # $MFT / file-system timeline
    browser: list[dict] = field(default_factory=list)       # browser history + downloads
    wmi: list[dict] = field(default_factory=list)           # WMI event-subscription persistence
    collection_warnings: list[str] = field(default_factory=list)
    source: str = ""
    host_name: str = ""

    @property
    def host(self) -> str:
        if self.host_name:
            return self.host_name
        for ev in self.events:
            if ev.get("computer"):
                return ev["computer"]
        return "unknown-host"


def load_evidence(
    directory: str | Path | None = None,
    events_path: str | Path | None = None,
    registry_path: str | Path | None = None,
    prefetch_path: str | Path | None = None,
    shimcache_path: str | Path | None = None,
    mft_path: str | Path | None = None,
    browser_path: str | Path | None = None,
    wmi_path: str | Path | None = None,
) -> Evidence:
    """Load evidence.

    With no arguments, loads the bundled native artifacts. Pass any of the export
    paths to ingest your own evidence (JSON / JSONL / CSV / .reg, plus the common
    forensic-tool exports) — they are auto-detected and normalized into the
    internal schema.
    """
    exports = (events_path, registry_path, prefetch_path, shimcache_path,
               mft_path, browser_path, wmi_path)
    if any(exports):
        from .normalize import (normalize_browser, normalize_events, normalize_mft,
                                normalize_prefetch, normalize_registry,
                                normalize_shimcache, normalize_wmi)
        src = " + ".join(str(p) for p in exports if p)
        return Evidence(
            events=normalize_events(events_path) if events_path else [],
            registry=normalize_registry(registry_path) if registry_path else [],
            prefetch=normalize_prefetch(prefetch_path) if prefetch_path else [],
            shimcache=normalize_shimcache(shimcache_path) if shimcache_path else [],
            filesystem=normalize_mft(mft_path) if mft_path else [],
            browser=normalize_browser(browser_path) if browser_path else [],
            wmi=normalize_wmi(wmi_path) if wmi_path else [],
            source=src,
        )

    d = Path(directory) if directory else DEFAULT_DIR
    registry = json.loads((d / "registry.json").read_text(encoding="utf-8-sig"))
    events = []
    with (d / "events.jsonl").open(encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return Evidence(registry=registry, events=events, source=str(d))
