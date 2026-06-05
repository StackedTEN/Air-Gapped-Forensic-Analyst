"""Collection packages.

A package is what the live collector produces: normalized artifact files plus a
`manifest.json` carrying chain-of-custody (case id, operator, host, collector
version, collection time) and a SHA-256 for every file. This module loads a
package into Evidence and verifies its integrity before analysis — because in a
real incident, evidence you can't vouch for is evidence you can't use.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import zipfile
from pathlib import Path

from .loader import Evidence
from .normalize import normalize_events


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def _resolve_dir(path: str | Path) -> tuple[Path, tempfile.TemporaryDirectory | None]:
    p = Path(path)
    if p.is_dir():
        return p, None
    if p.suffix.lower() == ".zip":
        tmp = tempfile.TemporaryDirectory()
        with zipfile.ZipFile(p) as z:
            z.extractall(tmp.name)
        root = Path(tmp.name)
        # collector zips the contents directly; handle a nested folder too
        inner = [d for d in root.iterdir() if d.is_dir()]
        if not (root / "manifest.json").exists() and len(inner) == 1:
            root = inner[0]
        return root, tmp
    raise ValueError(f"not a package (dir or .zip): {path}")


def verify_package(path: str | Path) -> dict:
    """Recompute every file's hash and compare to the manifest."""
    root, tmp = _resolve_dir(path)
    try:
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8-sig"))
        results = []
        for entry in manifest.get("files", []):
            fp = root / entry["name"]
            actual = _sha256(fp) if fp.exists() else None
            results.append({"name": entry["name"], "expected": entry["sha256"],
                            "actual": actual, "ok": actual == entry["sha256"].upper()})
        return {"ok": all(r["ok"] for r in results), "manifest": manifest, "files": results}
    finally:
        if tmp:
            tmp.cleanup()


def _load_json(root: Path, name: str) -> list[dict]:
    fp = root / name
    if not fp.exists():
        return []
    data = json.loads(fp.read_text(encoding="utf-8-sig"))
    return data if isinstance(data, list) else [data]


def load_package(path: str | Path, verify: bool = True) -> tuple[Evidence, dict]:
    """Load a collection package into Evidence, returning (evidence, manifest).

    Raises if integrity verification fails (unless verify=False).
    """
    root, tmp = _resolve_dir(path)
    try:
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8-sig"))
        if verify:
            v = verify_package(root)
            if not v["ok"]:
                bad = [f["name"] for f in v["files"] if not f["ok"]]
                raise ValueError(f"package integrity check failed for: {', '.join(bad)}")
        ev = Evidence(
            events=normalize_events(root / "events.json") if (root / "events.json").exists() else [],
            registry=_load_json(root, "registry.json"),
            processes=_load_json(root, "processes.json"),
            network=_load_json(root, "network.json"),
            users=_load_json(root, "users.json"),
            services=_load_json(root, "services.json"),
            programs=_load_json(root, "programs.json"),
            collection_warnings=list(manifest.get("warnings", []) or []),
            source=str(path),
            host_name=(manifest.get("host", {}) or {}).get("computer", ""),
        )
        return ev, manifest
    finally:
        if tmp:
            tmp.cleanup()
