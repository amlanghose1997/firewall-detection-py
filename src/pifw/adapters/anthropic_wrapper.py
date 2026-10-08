from __future__ import annotations

from typing import Any

from pifw.adapters.openai_wrapper import PromptInjectionBlocked
from pifw.firewall import Firewall
from pifw.models import Action, Source


class _MessagesProxy:
    def __init__(self, messages: Any, firewall: Firewall) -> None:
        self._messages = messages
        self._firewall = firewall

    def create(self, *args: Any, **kwargs: Any) -> Any:
        msgs = kwargs.get("messages", [])
        for msg in msgs:
            if isinstance(msg, dict):
                role = msg.get("role", "user")
                if role == "system":
                    continue
                content = msg.get("content", "")
                if isinstance(content, list):
                    content = " ".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
                else:
                    content = str(content)

                if content.strip():
                    verdict = self._firewall.scan(content, source=Source.USER)
                    if verdict.action == Action.BLOCK:
                        raise PromptInjectionBlocked(verdict)
                    elif verdict.action == Action.SANITIZE:
                        msg["content"] = verdict.sanitized_text

        response = self._messages.create(*args, **kwargs)

        if hasattr(response, "content") and response.content:
            for block in response.content:
                out_text = getattr(block, "text", "")
                if out_text.strip():
                    out_verdict = self._firewall.scan_output(out_text)
                    if out_verdict.action == Action.BLOCK:
                        raise PromptInjectionBlocked(out_verdict)

        return response


class AnthropicGuard:
    """Wraps Anthropic client to automatically scan request messages and output responses."""

    def __init__(self, client: Any, *, config: Any | None = None) -> None:
        self._client = client
        self._firewall = Firewall(config=config)

    @property
    def messages(self) -> _MessagesProxy:
        return _MessagesProxy(self._client.messages, self._firewall)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)
