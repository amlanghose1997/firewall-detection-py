
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pifw.models import Chunk


class Extractor(ABC):
    @abstractmethod
    def extract(self, payload: Any, *, source: str | None = None, origin: str | None = None) -> list[Chunk]:
        raise NotImplementedError

    def extract_text(self, payload: Any, *, source: str | None = None, origin: str | None = None) -> list[Chunk]:
        return self.extract(payload, source=source, origin=origin)
