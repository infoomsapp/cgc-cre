"""
Soft-flag -> hard-block promotion switch, per detector.

Every Phase 2/3 detector (payload checks, credential-stuffing) shipped
soft-flag-only by deliberate, low-risk default: log + record, never block,
while real-world false-positive rate accumulates. This module is the
promotion mechanism -- an env var per detector, defaulting to soft ("false")
so nothing changes until a human explicitly flips it after actually
observing that detector's real false-positive rate. Flipping the switch is
not something this code can decide for itself; the observation period is a
business decision, not a technical one.

GUARD_HARD_MODE_PAYLOAD=true    -> /governance/decision rejects (400) a
                                    request whose payload matches a pattern,
                                    instead of only soft-flagging it.
GUARD_HARD_MODE_STUFFING=true   -> a detected credential-stuffing pattern
                                    (3+ distinct emails from one IP) auto-
                                    blocks that IP via AuthSystem.block_user(),
                                    instead of only logging a warning.
"""

import os


def is_hard_mode(detector: str) -> bool:
    env_var = f"GUARD_HARD_MODE_{detector.upper()}"
    return os.getenv(env_var, "false").strip().lower() in ("1", "true", "yes", "on")
