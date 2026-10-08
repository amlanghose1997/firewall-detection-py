from __future__ import annotations

import re

from pifw.extractors.base import Extractor
from pifw.models import Chunk, Source, Trust


class CodeExtractor(Extractor):
    """Extract comments, docstrings, and string blocks from source code files."""

    def extract(self, data: bytes, *, origin: str | None = None) -> list[Chunk]:
        text = data.decode("utf-8", errors="replace")
        chunks: list[Chunk] = []

        # 1. Full code block
        chunks.append(
            Chunk(
                text=text,
                source=Source.CODE,
                trust=Trust.SEMI_TRUSTED,
                origin=origin,
            )
        )

        # 2. Single-line comments (# or //)
        for match in re.finditer(r"(?:#|//)\s*(.+)$", text, re.MULTILINE):
            comment = match.group(1).strip()
            if len(comment) > 5:
                chunks.append(
                    Chunk(
                        text=comment,
                        source=Source.CODE,
                        trust=Trust.UNTRUSTED,
                        hidden=True,
                        origin=f"{origin}:comment" if origin else "comment",
                    )
                )

        # 3. Multi-line comments /* ... */
        for match in re.finditer(r"/\*(.+?)\*/", text, re.DOTALL):
            comment = match.group(1).strip()
            if comment:
                chunks.append(
                    Chunk(
                        text=comment,
                        source=Source.CODE,
                        trust=Trust.UNTRUSTED,
                        hidden=True,
                        origin=f"{origin}:block_comment" if origin else "block_comment",
                    )
                )

        # 4. Triple-quoted docstrings (""" ... """ or ''' ... ''')
        for match in re.finditer(r'"""(.+?)"""|\'\'\'(.+?)\'\'\'', text, re.DOTALL):
            docstring = (match.group(1) or match.group(2) or "").strip()
            if docstring:
                chunks.append(
                    Chunk(
                        text=docstring,
                        source=Source.CODE,
                        trust=Trust.UNTRUSTED,
                        hidden=True,
                        origin=f"{origin}:docstring" if origin else "docstring",
                    )
                )

        return chunks
