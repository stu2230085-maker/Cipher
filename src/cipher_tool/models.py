"""Data models shared by operations and search."""
from __future__ import annotations
from dataclasses import dataclass, field

@dataclass(frozen=True)
class Candidate:
    data: bytes
    score: float
    history: tuple[str, ...] = field(default_factory=tuple)
    def text(self) -> str:
        return self.data.decode("utf-8", errors="replace")
