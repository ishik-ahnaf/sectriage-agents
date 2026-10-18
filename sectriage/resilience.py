"""Resilience helpers: timeout wrapper with cooperative cancellation."""
from __future__ import annotations

import threading
from typing import Any, Callable


class AgentTimeout(Exception):
    """Raised when an agent does not answer within its deadline."""


class AgentCancelled(Exception):
    """Raised inside an agent call that the orchestrator has already given up on."""


def run_with_timeout(fn: Callable[..., Any], args: tuple, timeout_s: float) -> Any:
    """Run fn(*args, cancel) in a daemon thread and wait at most timeout_s seconds.

    Python threads cannot be killed, so on timeout we set the `cancel` event. Agents
    check it (see BaseAgent.handle) and drop any late reply instead of logging or
    committing it - otherwise an abandoned call could emit a stale message after the
    conversation has moved on. Exceptions raised inside fn are re-raised in the caller.
    """
    box: dict[str, Any] = {}
    cancel = threading.Event()

    def target() -> None:
        try:
            box["value"] = fn(*args, cancel)
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            box["error"] = exc

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(timeout_s)
    if worker.is_alive():
        cancel.set()
        raise AgentTimeout(f"no reply within {timeout_s:.1f}s")
    if "error" in box:
        raise box["error"]
    return box["value"]
