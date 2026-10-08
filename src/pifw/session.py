
from __future__ import annotations

import time
from collections import defaultdict

from pydantic import BaseModel


class RiskEvent(BaseModel):
    timestamp: float
    risk: float
    label: str = ""


class SessionTracker:
    """Rolling risk tracker for multi-step jailbreak scenarios."""

    def __init__(self, *, window: int = 8, decay: float = 0.8, threshold: float = 0.75) -> None:
        self.window = window
        self.decay = decay
        self.threshold = threshold
        self._events: dict[str, list[RiskEvent]] = defaultdict(list)

    def record(self, session_id: str, risk: float, *, label: str = "") -> float:
        event = RiskEvent(timestamp=time.time(), risk=max(0.0, min(1.0, float(risk))), label=label)
        bucket = self._events[session_id]
        bucket.append(event)
        if len(bucket) > self.window:
            bucket.pop(0)
        return self.score(session_id)

    def score(self, session_id: str) -> float:
        events = self._events.get(session_id, [])
        total = 0.0
        for index, event in enumerate(reversed(events)):
            total += event.risk * (self.decay ** index)
        return min(1.0, total)

    def escalation(self, session_id: str) -> float:
        events = self._events.get(session_id, [])
        if not events:
            return 0.0
        # Repeated probes and multi-turn pattern-building should raise cumulative risk.
        unique_labels = {event.label for event in events if event.label}
        probes = sum(1 for event in events if "probe" in event.label.lower() or "jailbreak" in event.label.lower())
        repeated = max(0.0, (len(events) - 1) / max(1, self.window))
        return min(1.0, (self.score(session_id) * 0.7) + (probes / max(1, len(events))) + repeated + (0.15 if len(unique_labels) > 1 else 0.0))

    def maybe_alert(self, session_id: str, *, threshold: float | None = None) -> bool:
        threshold = self.threshold if threshold is None else threshold
        return self.score(session_id) >= threshold or self.escalation(session_id) >= threshold

    def track_turn(self, session_id: str, risk: float, *, label: str = "") -> dict[str, float | bool]:
        score = self.record(session_id, risk, label=label)
        return {"score": score, "alert": self.maybe_alert(session_id)}
