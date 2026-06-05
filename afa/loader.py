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
) -> Evidence:
    """Load evidence.

    With no arguments, loads the bundled native artifacts. Pass `events_path` /
    `registry_path` to ingest your own exports (JSON / JSONL / CSV / .reg) — they
    are auto-detected and normalized into the internal schema.
    """
    if events_path or registry_path:
        from .normalize import normalize_events, normalize_registry
        events = normalize_events(events_path) if events_path else []
        registry = normalize_registry(registry_path) if registry_path else []
        src = " + ".join(str(p) for p in (events_path, registry_path) if p)
        return Evidence(registry=registry, events=events, source=src)

    d = Path(directory) if directory else DEFAULT_DIR
    registry = json.loads((d / "registry.json").read_text(encoding="utf-8-sig"))
    events = []
    with (d / "events.jsonl").open(encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return Evidence(registry=registry, events=events, source=str(d))
