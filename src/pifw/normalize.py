from __future__ import annotations

import html
import re
import unicodedata

ZERO_WIDTH = (
    {chr(i) for i in range(0x200B, 0x200F + 1)}
    | {chr(i) for i in range(0x2060, 0x2065 + 1)}
    | {chr(0xFEFF)}
)
BIDI = {chr(i) for i in range(0x202A, 0x202E + 1)} | {
    chr(i) for i in range(0x2066, 0x2069 + 1)
}
TAG_CHARS = {chr(i) for i in range(0xE0000, 0xE007F + 1)}


def _homoglyph_fold(text: str) -> str:
    mapping = {
        "а": "a", "А": "A", "е": "e", "Е": "E", "о": "o", "О": "O", "р": "p", "Р": "P",
        "с": "c", "С": "C", "х": "x", "Х": "X", "к": "k", "К": "K", "м": "m", "М": "M",
        "у": "y", "У": "Y", "т": "t", "Т": "T", "в": "b", "В": "B", "і": "i", "І": "I",
        "й": "n", "И": "N", "г": "r", "Г": "R", "л": "l", "Л": "L", "з": "3", "З": "3",
        "φ": "f", "χ": "x", "θ": "th", "δ": "d", "β": "b", "ω": "w", "ο": "o", "α": "a",
    }
    return "".join(mapping.get(ch, ch) for ch in text)


def normalize_text(text: str) -> tuple[str, dict[int, int], dict[str, bool]]:
    """Normalize text and return normalized version, an offset map, and flags."""
    original = text
    flags = {"obfuscation": False, "hidden_chars": False}
    text = unicodedata.normalize("NFKC", text)
    text = html.unescape(text)
    text = "".join(
        ch for ch in text if ch not in ZERO_WIDTH and ch not in BIDI and ch not in TAG_CHARS
    )
    if any(ch in ZERO_WIDTH or ch in BIDI or ch in TAG_CHARS for ch in original):
        flags["hidden_chars"] = True
        flags["obfuscation"] = True
    compact = re.sub(r"\s+", " ", text).strip()
    folded = _homoglyph_fold(compact)
    folded = re.sub(r"(?i)(?<=\w)1(?=\w)", "i", folded)
    folded = folded.replace("0", "o")
    offset_map = {i: i for i in range(len(original))}
    return folded, offset_map, flags