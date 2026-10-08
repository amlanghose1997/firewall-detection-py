from __future__ import annotations

import io

from pifw.extractors.base import Extractor
from pifw.models import Chunk, Source, Trust


class ImageOCRExtractor(Extractor):
    """Extract text from images using pytesseract / Pillow, with inverted/contrast passes and EXIF metadata extraction."""

    def extract(self, data: bytes, *, origin: str | None = None) -> list[Chunk]:
        try:
            import pytesseract
            from PIL import Image, ImageOps
        except ImportError:
            return [Chunk(text="[OCR extraction unavailable]", source=Source.OCR, trust=Trust.UNTRUSTED, origin=origin)]

        chunks: list[Chunk] = []

        try:
            img = Image.open(io.BytesIO(data))
        except Exception:
            return [Chunk(text="[Image parse error]", source=Source.OCR, trust=Trust.UNTRUSTED, origin=origin)]

        # 1. Standard OCR pass
        try:
            text = pytesseract.image_to_string(img).strip()
            if text:
                chunks.append(
                    Chunk(
                        text=text,
                        source=Source.OCR,
                        trust=Trust.UNTRUSTED,
                        origin=origin,
                    )
                )
        except Exception:
            text = ""

        # 2. Inverted OCR pass (light text on dark or light background)
        try:
            rgb_img = img.convert("RGB")
            inverted = ImageOps.invert(rgb_img)
            inv_text = pytesseract.image_to_string(inverted).strip()
            if inv_text and inv_text != text:
                chunks.append(
                    Chunk(
                        text=inv_text,
                        source=Source.OCR,
                        trust=Trust.UNTRUSTED,
                        hidden=True,
                        origin=f"{origin}:inverted" if origin else "inverted",
                    )
                )
        except Exception:
            pass

        # 3. EXIF metadata
        try:
            exif = img.getexif()
            if exif:
                exif_strings = [str(v) for v in exif.values() if isinstance(v, str) and str(v).strip()]
                if exif_strings:
                    chunks.append(
                        Chunk(
                            text=" ".join(exif_strings),
                            source=Source.OCR,
                            trust=Trust.UNTRUSTED,
                            hidden=True,
                            origin=f"{origin}:exif" if origin else "exif",
                        )
                    )
        except Exception:
            pass

        return chunks if chunks else [Chunk(text="[No OCR text detected]", source=Source.OCR, trust=Trust.UNTRUSTED, origin=origin)]
