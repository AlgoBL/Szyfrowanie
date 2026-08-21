"""
utils/logger.py – Operation history logger.

Writes a JSON-Lines log file and exposes helpers to read recent history.
"""

from __future__ import annotations

import json
import datetime
from pathlib import Path
from typing import Any, Dict, List

LOG_FILENAME = 'history.jsonl'


class OperationLogger:
    """Append-only JSON-Lines operation logger."""

    def __init__(self, log_dir: Path):
        self.log_path = log_dir / LOG_FILENAME
        log_dir.mkdir(parents=True, exist_ok=True)

    def log(self, operation: str, **kwargs: Any) -> None:
        """
        Append a log entry.

        Args:
            operation: 'encrypt', 'decrypt', 'keygen', 'delete', etc.
            **kwargs:  Additional key-value metadata (filenames, key names…).
        """
        entry: Dict[str, Any] = {
            'ts': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'op': operation,
            **kwargs,
        }
        with open(self.log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')

    def read_all(self) -> List[Dict[str, Any]]:
        """Return all log entries as a list of dicts (oldest first)."""
        if not self.log_path.exists():
            return []
        entries = []
        with open(self.log_path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return entries

    def read_recent(self, n: int = 100) -> List[Dict[str, Any]]:
        """Return the last *n* log entries (most recent first)."""
        return list(reversed(self.read_all()[-n:]))

    def clear(self) -> None:
        """Delete all history."""
        if self.log_path.exists():
            self.log_path.unlink()
