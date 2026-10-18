"""Structured communication logging.

Every event is written twice:
  * logs/<run_id>.jsonl  - machine-readable (one JSON object per line)
  * logs/<run_id>.log    - human-readable text (what you screenshot for the report)
and optionally echoed to the console.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime, timezone

COLOURS = {"INFO": "\033[0m", "WARNING": "\033[33m", "ERROR": "\033[31m", "DEBUG": "\033[90m"}
RESET = "\033[0m"


def _fmt_value(value) -> str:
    text = str(value)
    if len(text) > 80:
        text = text[:77] + "..."
    return f'"{text}"' if (" " in text or text == "") else text


class CommLog:
    def __init__(self, log_dir: str = "logs", run_id: str | None = None, console: bool = True):
        os.makedirs(log_dir, exist_ok=True)
        self.run_id = run_id or datetime.now().strftime("run-%Y%m%d-%H%M%S")
        self.jsonl_path = os.path.join(log_dir, f"{self.run_id}.jsonl")
        self.text_path = os.path.join(log_dir, f"{self.run_id}.log")
        self._jsonl = open(self.jsonl_path, "a", encoding="utf-8")
        self._text = open(self.text_path, "a", encoding="utf-8")
        self._lock = threading.Lock()
        self.console = console
        self._colour = console and sys.stdout.isatty()

    def event(self, component: str, event: str, level: str = "INFO", **fields) -> None:
        now = datetime.now(timezone.utc)
        record = {"ts": now.isoformat(timespec="milliseconds"), "run_id": self.run_id,
                  "level": level, "component": component, "event": event, **fields}
        clock = now.astimezone().strftime("%H:%M:%S.%f")[:-3]
        body = " ".join(f"{k}={_fmt_value(v)}" for k, v in fields.items())
        line = f"{clock} | {level:<7} | {component:<12} | {event:<18} | {body}"
        with self._lock:
            self._jsonl.write(json.dumps(record, default=str) + "\n")
            self._jsonl.flush()
            self._text.write(line + "\n")
            self._text.flush()
            if self.console:
                if self._colour:
                    line = f"{COLOURS.get(level, '')}{line}{RESET}"
                print(line, flush=True)

    def close(self) -> None:
        with self._lock:
            self._jsonl.close()
            self._text.close()
