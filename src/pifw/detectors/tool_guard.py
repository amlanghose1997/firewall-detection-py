
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse


class ToolGuard:
    """Allowlist, argument validation, and intent alignment for tool calls."""

    def __init__(self, allowlist: set[str] | None = None) -> None:
        self.allowlist = allowlist or {"search", "lookup", "read_file", "send_email"}

    def validate(self, name: str, args: dict[str, Any], *, user_intent: str = "") -> tuple[bool, str]:
        if name not in self.allowlist:
            return False, f"tool {name!r} is not allowlisted"

        if name in {"search", "lookup"}:
            query = str(args.get("query") or "").strip()
            if not query:
                return False, "query must not be empty"

        if name == "read_file":
            rel_path = str(args.get("path") or "")
            if not rel_path.strip():
                return False, "read_file path must not be empty"
            normalized = rel_path.replace("\\", "/")
            # Treat absolute paths and traversal attempts as invalid regardless of OS semantics.
            if normalized.startswith("/") or normalized.startswith("~/") or normalized.startswith("//"):
                return False, "read_file path must stay within workspace"
            if len(normalized) >= 2 and normalized[1] == ":":
                return False, "read_file path must stay within workspace"
            parts = normalized.split("/")
            if any(part == ".." for part in parts):
                return False, "read_file path escapes workspace"
            if rel_path.startswith("~"):
                return False, "read_file path must stay within workspace"

        if name in {"send_email", "post_message"}:
            recipient = str(args.get("recipient") or "")
            if not recipient or "@" not in recipient:
                return False, "recipient must be a valid email address"

        if name == "fetch_url":
            url = str(args.get("url") or "")
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"}:
                return False, "fetch_url requires an http or https URL"
            if parsed.hostname in {"localhost", "127.0.0.1", "169.254.169.254"}:
                return False, "fetch_url target is not allowed"

        if user_intent:
            lower_intent = user_intent.lower()
            if name not in {"search", "lookup"} and name.lower() not in lower_intent:
                if not any(token in lower_intent for token in ["file", "email", "search", "lookup", "download", "fetch"]):
                    return False, f"tool {name!r} is not aligned with user intent"

        return True, "ok"
