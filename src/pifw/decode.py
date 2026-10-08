from __future__ import annotations

import base64
import codecs
import html
import re
from urllib.parse import unquote


def _safe_printable(candidate: str) -> bool:
    if not candidate or len(candidate) < 4:
        return False
    printable = sum(ch.isprintable() or ch in "\n\r\t" for ch in candidate)
    ratio = printable / max(len(candidate), 1)
    return ratio > 0.85 and any(ch.isalpha() for ch in candidate)


def _decode_base64(blob: str) -> str | None:
    cleaned = re.sub(r"[^A-Za-z0-9+/=]", "", blob)
    if len(cleaned) < 8:
        return None
    try:
        out = base64.b64decode(cleaned, validate=False)
        decoded = out.decode("utf-8", errors="ignore")
    except Exception:
        return None
    return decoded if _safe_printable(decoded) else None


def _decode_hex(blob: str) -> str | None:
    cleaned = re.sub(r"[^0-9a-fA-F]", "", blob)
    if len(cleaned) < 8:
        return None
    try:
        out = bytes.fromhex(cleaned)
        decoded = out.decode("utf-8", errors="ignore")
    except Exception:
        return None
    return decoded if _safe_printable(decoded) else None


def _decode_url(blob: str) -> str | None:
    decoded = unquote(blob)
    return decoded if _safe_printable(decoded) and decoded != blob else None


def _decode_html(blob: str) -> str | None:
    decoded = html.unescape(blob)
    return decoded if _safe_printable(decoded) and decoded != blob else None


def _decode_unicode_escapes(blob: str) -> str | None:
    try:
        decoded = codecs.decode(blob, "unicode_escape")
    except Exception:
        return None
    return decoded if _safe_printable(decoded) and decoded != blob else None


def _decode_rot13(blob: str) -> str:
    return blob.translate(
        str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
        )
    )


def decode_candidates(text: str, depth: int = 3) -> list[str]:
    seen: set[str] = {text}
    out: list[str] = []
    queue = [text]

    for _ in range(depth):
        next_queue: list[str] = []
        for item in queue:
            patterns = [
                re.findall(r"(?:[A-Za-z0-9+/]{20,}={0,2}|[A-Fa-f0-9]{16,})", item),
                re.findall(r"(?:%[0-9A-Fa-f]{2})+", item),
                re.findall(r"(?:\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2})+", item),
                re.findall(r"&[#A-Za-z0-9]+;", item),
            ]
            for pat in patterns:
                for blob in pat:
                    for decoder in (_decode_base64, _decode_hex, _decode_url, _decode_html, _decode_unicode_escapes):
                        try:
                            decoded = decoder(blob)
                        except Exception:
                            continue
                        if decoded and decoded not in seen:
                            seen.add(decoded)
                            out.append(decoded)
                            next_queue.append(decoded)

            rot = _decode_rot13(item)
            if rot not in seen and rot != item and _safe_printable(rot):
                seen.add(rot)
                out.append(rot)
                next_queue.append(rot)

        queue = next_queue
        if not queue:
            break

    return out