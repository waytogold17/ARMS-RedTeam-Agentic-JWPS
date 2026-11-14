"""Journal de la Red Team, chaîné par hash : chaque action d'agent est traçable et non modifiable sans détection."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str).encode()


class RedTeamLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.entries: list[dict] = []

    def append(self, agent: str, event: str, **data) -> dict:
        prev = self.entries[-1]["hash"] if self.entries else GENESIS
        e = {"seq": len(self.entries) + 1, "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "agent": agent, "event": event, "data": data, "prev": prev}
        e["hash"] = hashlib.sha256(prev.encode() + _canon(e)).hexdigest()
        self.entries.append(e)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(_canon(e).decode() + "\n")
        return e

    @staticmethod
    def verify(path: Path) -> tuple[bool, int]:
        prev, n = GENESIS, 0
        for line in path.read_text(encoding="utf-8").splitlines():
            e = json.loads(line)
            h = e.pop("hash")
            if e["prev"] != prev or hashlib.sha256(prev.encode() + _canon(e)).hexdigest() != h:
                return False, n
            prev, n = h, n + 1
        return True, n
