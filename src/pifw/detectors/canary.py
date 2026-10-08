
from __future__ import annotations

import secrets


class CanaryGuard:
    def __init__(self, *, prefix: str = "pifw-canary") -> None:
        self.prefix = prefix
        self._tokens: dict[str, str] = {}

    def generate(self, session_id: str) -> str:
        token = f"{self.prefix}-{session_id}-{secrets.token_hex(8)}"
        self._tokens[session_id] = token
        return token

    def inject(self, system_prompt: str, session_id: str) -> tuple[str, str]:
        token = self.generate(session_id)
        updated = f"{system_prompt}\n[canary-token:{token}]"
        return updated, token

    def check(self, text: str, token: str | None = None) -> bool:
        if token is None:
            return any(value in str(text) for value in self._tokens.values())
        return token in str(text)

    def last_token_for(self, session_id: str) -> str | None:
        return self._tokens.get(session_id)
