from __future__ import annotations

import json
from typing import Any

from pifw.extractors.base import Extractor
from pifw.extractors.html import HTMLExtractor
from pifw.extractors.text import TextExtractor
from pifw.models import Chunk, Source

MAGIC_BYTES = {
    b"%PDF": "pdf",
    b"PK\x03\x04": "docx",
    b"\x89PNG": "image",
    b"\xff\xd8\xff": "image",
    b"GIF8": "image",
    b"BM": "image",
}


def _detect_type(data: bytes, filename: str | None = None) -> str:
    for magic, ftype in MAGIC_BYTES.items():
        if data.startswith(magic):
            return ftype

    if filename:
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        ext_map = {
            "pdf": "pdf",
            "docx": "docx",
            "doc": "docx",
            "eml": "email",
            "msg": "email",
            "md": "markdown",
            "markdown": "markdown",
            "json": "json",
            "py": "code",
            "js": "code",
            "ts": "code",
            "java": "code",
            "c": "code",
            "cpp": "code",
            "rs": "code",
            "go": "code",
            "png": "image",
            "jpg": "image",
            "jpeg": "image",
            "gif": "image",
            "bmp": "image",
            "html": "html",
            "htm": "html",
        }
        if ext in ext_map:
            return ext_map[ext]

    text = data.decode("utf-8", errors="replace")[:1000].lower()
    if "<html" in text or "<body" in text or "<!doctype html" in text:
        return "html"
    stripped = text.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            json.loads(data.decode("utf-8", errors="replace"))
            return "json"
        except Exception:
            pass

    return "text"


def get_extractor(filetype: str) -> Extractor:
    if filetype == "pdf":
        from pifw.extractors.pdf import PDFExtractor

        return PDFExtractor()
    if filetype == "docx":
        from pifw.extractors.docx import DOCXExtractor

        return DOCXExtractor()
    if filetype == "email":
        from pifw.extractors.email_ext import EmailExtractor

        return EmailExtractor()
    if filetype == "markdown":
        from pifw.extractors.markdown import MarkdownExtractor

        return MarkdownExtractor()
    if filetype == "json":
        from pifw.extractors.json_api import JSONAPIExtractor

        return JSONAPIExtractor()
    if filetype == "code":
        from pifw.extractors.code import CodeExtractor

        return CodeExtractor()
    if filetype == "image":
        from pifw.extractors.image_ocr import ImageOCRExtractor

        return ImageOCRExtractor()
    if filetype == "html":
        return HTMLExtractor()

    return TextExtractor()


def extract_payload(
    payload: Any,
    *,
    source: str | None = None,
    filename: str | None = None,
    origin: str | None = None,
) -> list[Chunk]:
    if isinstance(payload, dict):
        from pifw.extractors.json_api import JSONAPIExtractor

        data_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return JSONAPIExtractor().extract(data_bytes, origin=origin or "dict")

    if isinstance(payload, (list, tuple)):
        from pifw.extractors.json_api import JSONAPIExtractor

        data_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return JSONAPIExtractor().extract(data_bytes, origin=origin or "list")

    if isinstance(payload, str):
        data_bytes = payload.encode("utf-8")
    elif isinstance(payload, (bytes, bytearray)):
        data_bytes = bytes(payload)
    else:
        data_bytes = str(payload).encode("utf-8")

    filetype = _detect_type(data_bytes, filename=filename)
    extractor = get_extractor(filetype)
    chunks = extractor.extract(data_bytes, origin=origin or filename)

    if source:
        try:
            src_enum = Source(source)
            for c in chunks:
                c.source = src_enum
        except ValueError:
            pass

    return chunks
