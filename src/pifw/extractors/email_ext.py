from __future__ import annotations

import email
from email import policy as email_policy

from pifw.extractors.base import Extractor
from pifw.models import Chunk, Source, Trust


class EmailExtractor(Extractor):
    """Extract headers, plain text body, HTML body parts, and attachment filenames from .eml files."""

    def extract(self, data: bytes, *, origin: str | None = None) -> list[Chunk]:
        chunks: list[Chunk] = []
        try:
            msg = email.message_from_bytes(data, policy=email_policy.default)
        except Exception:
            return [Chunk(text=data.decode("utf-8", errors="replace"), source=Source.EMAIL, trust=Trust.UNTRUSTED, origin=origin)]

        # 1. Important Headers
        headers = []
        for key in ("From", "To", "Cc", "Bcc", "Subject", "Reply-To", "Return-Path"):
            val = msg.get(key)
            if val:
                headers.append(f"{key}: {val}")
        if headers:
            chunks.append(
                Chunk(
                    text="\n".join(headers),
                    source=Source.EMAIL,
                    trust=Trust.UNTRUSTED,
                    origin=f"{origin}:headers" if origin else "headers",
                )
            )

        # 2. Body parts
        for part in msg.walk():
            content_type = part.get_content_type()
            filename = part.get_filename()

            if filename:
                chunks.append(
                    Chunk(
                        text=f"[attachment: {filename} ({content_type})]",
                        source=Source.EMAIL,
                        trust=Trust.UNTRUSTED,
                        hidden=True,
                        origin=f"{origin}:attachment:{filename}" if origin else f"attachment:{filename}",
                    )
                )

            if content_type == "text/plain" and not filename:
                try:
                    payload = part.get_content()
                    if isinstance(payload, str) and payload.strip():
                        chunks.append(
                            Chunk(
                                text=payload,
                                source=Source.EMAIL,
                                trust=Trust.UNTRUSTED,
                                origin=f"{origin}:text_body" if origin else "text_body",
                            )
                        )
                except Exception:
                    pass

            elif content_type == "text/html" and not filename:
                try:
                    payload = part.get_content()
                    if isinstance(payload, str) and payload.strip():
                        from pifw.extractors.html import HTMLExtractor

                        html_chunks = HTMLExtractor().extract(
                            payload.encode("utf-8", errors="replace"),
                            origin=f"{origin}:html_body" if origin else "html_body",
                        )
                        chunks.extend(html_chunks)
                except Exception:
                    pass

        return chunks if chunks else [Chunk(text=data.decode("utf-8", errors="replace"), source=Source.EMAIL, trust=Trust.UNTRUSTED, origin=origin)]
