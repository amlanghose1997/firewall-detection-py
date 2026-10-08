
from __future__ import annotations

from pifw.extractors.base import Extractor
from pifw.models import Chunk, Source


class TextExtractor(Extractor):
    def extract(self, payload, *, source: str | None = None, origin: str | None = None) -> list[Chunk]:
        text = payload if isinstance(payload, str) else str(payload)
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return [
            Chunk(
                text=text,
                source=Source(source) if source else Source.USER,
                origin=origin,
                hidden="display:none" in text.lower() or "visibility:hidden" in text.lower(),
                meta={"extractor": "text", "line_count": len(lines)},
            )
        ]
