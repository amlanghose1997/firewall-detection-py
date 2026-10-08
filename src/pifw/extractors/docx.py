from __future__ import annotations

import io

from pifw.extractors.base import Extractor
from pifw.models import Chunk, Source, Trust


class DOCXExtractor(Extractor):
    """Extract text from Microsoft Word documents, including hidden runs, comments, headers/footers, and tables."""

    def extract(self, data: bytes, *, origin: str | None = None) -> list[Chunk]:
        try:
            from docx import Document
            from docx.oxml.ns import qn
        except ImportError:
            return [Chunk(text="[DOCX extraction unavailable]", source=Source.DOCX, trust=Trust.UNTRUSTED, origin=origin)]

        try:
            doc = Document(io.BytesIO(data))
        except Exception:
            return [Chunk(text="[DOCX parse error]", source=Source.DOCX, trust=Trust.UNTRUSTED, origin=origin)]

        chunks: list[Chunk] = []

        # 1. Main body text
        body_text = "\n".join(p.text for p in doc.paragraphs if p.text.strip())
        if body_text:
            chunks.append(
                Chunk(
                    text=body_text,
                    source=Source.DOCX,
                    trust=Trust.UNTRUSTED,
                    origin=origin,
                )
            )

        # 2. Hidden runs (w:vanish element)
        for para in doc.paragraphs:
            for run in para.runs:
                try:
                    rpr = run._element.find(qn("w:rPr"))
                    if rpr is not None and rpr.find(qn("w:vanish")) is not None:
                        if run.text.strip():
                            chunks.append(
                                Chunk(
                                    text=run.text,
                                    source=Source.DOCX,
                                    trust=Trust.UNTRUSTED,
                                    hidden=True,
                                    origin=f"{origin}:hidden_run" if origin else "hidden_run",
                                )
                            )
                except Exception:
                    continue

        # 3. Headers and Footers
        for sec_idx, section in enumerate(doc.sections):
            for hdr in (section.header, section.footer):
                if hdr:
                    hdr_text = "\n".join(p.text for p in hdr.paragraphs if p.text.strip())
                    if hdr_text:
                        chunks.append(
                            Chunk(
                                text=hdr_text,
                                source=Source.DOCX,
                                trust=Trust.UNTRUSTED,
                                hidden=True,
                                origin=f"{origin}:section_{sec_idx}_hdr" if origin else f"section_{sec_idx}_hdr",
                            )
                        )

        # 4. Tables
        for table_idx, table in enumerate(doc.tables):
            table_lines = []
            for row in table.rows:
                row_str = " | ".join(cell.text.strip() for cell in row.cells if cell.text.strip())
                if row_str:
                    table_lines.append(row_str)
            if table_lines:
                chunks.append(
                    Chunk(
                        text="\n".join(table_lines),
                        source=Source.DOCX,
                        trust=Trust.UNTRUSTED,
                        origin=f"{origin}:table_{table_idx}" if origin else f"table_{table_idx}",
                    )
                )

        return chunks
