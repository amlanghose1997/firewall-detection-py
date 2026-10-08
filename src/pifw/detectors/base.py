from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pifw.models import Finding, ScanContext


class Detector(ABC):
    name: str = "base"

    @abstractmethod
    def scan(self, chunk: Any, ctx: ScanContext) -> list[Finding]:
        raise NotImplementedError


def register_detector(name: str, detector: Detector) -> None:
    detectors = globals().get("_DETECTORS", {})
    detectors[name] = detector
    globals()["_DETECTORS"] = detectors


def get_registered_detectors() -> dict[str, Detector]:
    return globals().get("_DETECTORS", {})