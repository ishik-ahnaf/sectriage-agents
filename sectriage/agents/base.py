"""Common behaviour for all agents: structured logging of received/sent messages."""
from __future__ import annotations

import threading
from typing import Any

from ..logger import CommLog
from ..protocol import Message
from ..resilience import AgentCancelled


class BaseAgent:
    name = "base"

    def __init__(self, comm: CommLog):
        self.comm = comm

    # The orchestrator calls handle(); subclasses implement process().
    def handle(self, msg: Message, cancel: threading.Event | None = None) -> Any:
        self.comm.event(self.name, "RECEIVED", **msg.summary())
        try:
            reply = self.process(msg, cancel)
            if cancel is not None and cancel.is_set():
                raise AgentCancelled()
        except AgentCancelled:
            self.comm.event(self.name, "STALE_REPLY_DROPPED", level="WARNING",
                            msg=msg.message_id, alert=msg.alert_id)
            raise
        self._log_sent(reply, msg.alert_id)
        return reply

    def process(self, msg: Message, cancel: threading.Event | None = None) -> Any:  # pragma: no cover
        raise NotImplementedError

    def make_reply(self, incoming: Message, receiver: str, intent: str, content: dict) -> Message:
        return Message(sender=self.name, receiver=receiver, intent=intent, content=content,
                       conversation_id=incoming.conversation_id, step=incoming.step,
                       in_reply_to=incoming.message_id)

    def _log_sent(self, reply: Any, alert_id: str) -> None:
        if isinstance(reply, Message):
            self.comm.event(self.name, "SENT", **reply.summary())
        elif isinstance(reply, dict):
            self.comm.event(self.name, "SENT", msg=reply.get("message_id", "?"),
                            to=reply.get("receiver", "?"), intent=reply.get("intent", "?"),
                            alert=alert_id)
        else:
            self.comm.event(self.name, "SENT", raw=str(reply)[:60], alert=alert_id)
