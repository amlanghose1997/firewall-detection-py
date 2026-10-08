
from __future__ import annotations

from html.parser import HTMLParser

from pifw.extractors.base import Extractor
from pifw.models import Chunk, Source


class _HTMLTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.chunks: list[str] = []
        self.hidden = False
        self._skip_stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {str(k).lower(): (v or "") for k, v in attrs}
        if tag in {"script", "style", "template"}:
            self._skip_stack.append(tag)
        if attr_map.get("hidden") is not None or attr_map.get("aria-hidden") == "true":
            self.hidden = True
        if any(token in (attr_map.get("style") or "").lower() for token in ["display:none", "visibility:hidden", "font-size:0", "opacity:0", "color:transparent"]):
            self.hidden = True

    def handle_endtag(self, tag: str) -> None:
        if self._skip_stack and self._skip_stack[-1] == tag:
            self._skip_stack.pop()

    def handle_data(self, data: str) -> None:
        if not data or self._skip_stack:
            return
        if data.strip():
            self.chunks.append(data.strip())

    def handle_comment(self, data: str) -> None:
        if data.strip():
            self.chunks.append(data.strip())
            self.hidden = True


class HTMLExtractor(Extractor):
    def extract(self, payload, *, source: str | None = None, origin: str | None = None) -> list[Chunk]:
        text = payload if isinstance(payload, str) else str(payload)
        parser = _HTMLTextParser()
        parser.feed(text)
        visible_text = "\n".join(part for part in parser.chunks if part)
        return [
            Chunk(
                text=visible_text or text,
                source=Source.HTML if source is None else Source(source),
                origin=origin,
                hidden=parser.hidden or "display:none" in text.lower() or "visibility:hidden" in text.lower(),
                meta={"extractor": "html", "visible_chars": len(visible_text)},
            )
        ]
