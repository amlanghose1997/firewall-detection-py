from __future__ import annotations

import re

from pifw.extractors.base import Extractor
from pifw.models import Chunk, Source, Trust


class MarkdownExtractor(Extractor):
    """Extract Markdown text, HTML comments, front-matter, and image alt texts."""

    def extract(self, data: bytes, *, origin: str | None = None) -> list[Chunk]:
        text = data.decode("utf-8", errors="replace")
        chunks: list[Chunk] = []

        # 1. Main text content
        chunks.append(
            Chunk(
                text=text,
                source=Source.MARKDOWN,
                trust=Trust.UNTRUSTED,
                origin=origin,
            )
        )

        # 2. Hidden HTML comments <!-- ... -->
        for match in re.finditer(r"<!--(.*?)-->", text, re.DOTALL):
            comment = match.group(1).strip()
            if comment:
                chunks.append(
                    Chunk(
                        text=comment,
                        source=Source.MARKDOWN,
                        trust=Trust.UNTRUSTED,
                        hidden=True,
                        origin=f"{origin}:html_comment" if origin else "html_comment",
                    )
                )

        # 3. YAML Front-matter (between --- ... --- at top)
        fm = re.match(r"^---\s*\n(.*?)\n---", text, re.DOTALL)
        if fm:
            chunks.append(
                Chunk(
                    text=fm.group(1).strip(),
                    source=Source.MARKDOWN,
                    trust=Trust.UNTRUSTED,
                    hidden=True,
                    origin=f"{origin}:frontmatter" if origin else "frontmatter",
                )
            )

        # 4. Image alt texts ![alt](url)
        for match in re.finditer(r"!\[([^\]]+)\]", text):
            alt = match.group(1).strip()
            if alt:
                chunks.append(
                    Chunk(
                        text=alt,
                        source=Source.MARKDOWN,
                        trust=Trust.UNTRUSTED,
                        hidden=True,
                        origin=f"{origin}:image_alt" if origin else "image_alt",
                    )
                )

        return chunks
