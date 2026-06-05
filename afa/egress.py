"""Air-gap guard.

The default posture is zero egress: the only model traffic allowed is to a
local engine on localhost. Sending evidence to a third-party API is possible,
but it is opt-in, must be requested explicitly, and prints a warning — because
it breaks the guarantee that forensic data never leaves the host.

This is enforced structurally rather than by policy: the cloud provider cannot
be constructed unless egress has been explicitly allowed.
"""

from __future__ import annotations

import os

LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


class EgressBlocked(RuntimeError):
    pass


def egress_allowed() -> bool:
    return os.environ.get("AFA_ALLOW_EGRESS", "").lower() in ("1", "true", "yes")


def assert_local(url: str) -> None:
    """Allow only loopback URLs unless egress has been explicitly enabled."""
    if any(h in url for h in LOCAL_HOSTS):
        return
    if egress_allowed():
        return
    raise EgressBlocked(
        f"Refusing to send evidence to {url!r}. This tool is air-gapped by default.\n"
        "Local model traffic (localhost) is always allowed. To use a remote API, set "
        "AFA_ALLOW_EGRESS=1 — but understand that this sends forensic data off the host."
    )


EGRESS_WARNING = (
    "  egress enabled — evidence will be sent to a third-party API. "
    "This breaks the air-gap. Use only on data you are cleared to share."
)
