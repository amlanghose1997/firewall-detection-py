from __future__ import annotations

from pifw.extractors.base import Extractor
from pifw.models import Chunk, Source, Trust


class PDFExtractor(Extractor):
    """Extract text from PDFs, including hidden/tiny/white text and form fields."""

    def extract(self, data: bytes, *, origin: str | None = None) -> list[Chunk]:
        try:
            import fitz  # PyMuPDF
        except ImportError:
            return [Chunk(text="[PDF extraction unavailable]", source=Source.PDF, trust=Trust.UNTRUSTED, origin=origin)]

        chunks: list[Chunk] = []
        try:
            doc = fitz.open(stream=data, filetype="pdf")
        except Exception:
            return [Chunk(text="[PDF parse error]", source=Source.PDF, trust=Trust.UNTRUSTED, origin=origin)]

        for page_num, page in enumerate(doc):
            page_origin = f"{origin}#page{page_num + 1}" if origin else f"page{page_num + 1}"

            # 1. Visible text layer
            text = page.get_text("text")
            if text.strip():
                chunks.append(
                    Chunk(
                        text=text,
                        source=Source.PDF,
                        trust=Trust.UNTRUSTED,
                        origin=page_origin,
                    )
                )

            # 2. Detailed text blocks check for tiny/white/off-screen text
            try:
                blocks = page.get_text("dict", flags=fitz.TEXT_PRESERVE_WHITESPACE).get("blocks", [])
                for block in blocks:
                    for line in block.get("lines", []):
                        for span in line.get("spans", []):
                            font_size = span.get("size", 12)
                            color = span.get("color", 0)
                            span_text = str(span.get("text", "")).strip()
                            if span_text and (font_size < 3 or color in (0xFFFFFF, 16777215)):
                                chunks.append(
                                    Chunk(
                                        text=span_text,
                                        source=Source.PDF,
                                        trust=Trust.UNTRUSTED,
                                        hidden=True,
                                        origin=f"{page_origin}:hidden_text",
                                        meta={"font_size": font_size, "color": hex(color)},
                                    )
                                )
            except Exception:
                pass

            # 3. Annotations
            try:
                for annot in page.annots() or []:
                    info = annot.info
                    content = str(info.get("content", "")).strip()
                    if content:
                        chunks.append(
                            Chunk(
                                text=content,
                                source=Source.PDF,
                                trust=Trust.UNTRUSTED,
                                hidden=True,
                                origin=f"{page_origin}:annotation",
                            )
                        )
            except Exception:
                pass

        # 4. Document Metadata
        try:
            meta = doc.metadata or {}
            meta_text = " ".join(str(v) for v in meta.values() if v)
            if meta_text.strip():
                chunks.append(
                    Chunk(
                        text=meta_text,
                        source=Source.PDF,
                        trust=Trust.UNTRUSTED,
                        hidden=True,
                        origin=f"{origin}:metadata" if origin else "metadata",
                    )
                )
        except Exception:
            pass

        doc.close()
        return chunks
