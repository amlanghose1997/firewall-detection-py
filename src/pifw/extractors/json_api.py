from __future__ import annotations

import json

from pifw.extractors.base import Extractor
from pifw.models import Chunk, Source, Trust


class JSONAPIExtractor(Extractor):
    """Walk JSON structure recursively and extract string fields with JSONPath origins."""

    def extract(self, data: bytes, *, origin: str | None = None) -> list[Chunk]:
        text = data.decode("utf-8", errors="replace")
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return [Chunk(text=text, source=Source.API, trust=Trust.UNTRUSTED, origin=origin)]

        chunks: list[Chunk] = []
        self._walk(parsed, "$", chunks, origin)
        return chunks if chunks else [Chunk(text=text, source=Source.API, trust=Trust.UNTRUSTED, origin=origin)]

    def _walk(self, obj: object, path: str, chunks: list[Chunk], origin: str | None) -> None:
        if isinstance(obj, str) and obj.strip():
            chunks.append(
                Chunk(
                    text=obj,
                    source=Source.API,
                    trust=Trust.UNTRUSTED,
                    origin=f"{origin}:{path}" if origin else path,
                )
            )
        elif isinstance(obj, dict):
            for key, value in obj.items():
                self._walk(value, f"{path}.{key}", chunks, origin)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._walk(item, f"{path}[{i}]", chunks, origin)
