from __future__ import annotations

from typing import Any

from pifw.firewall import Firewall
from pifw.models import Action, Source, Verdict


class PromptInjectionBlocked(Exception):
    def __init__(self, verdict: Verdict) -> None:
        self.verdict = verdict
        super().__init__(f"Prompt injection blocked by pifw: {verdict.action.value} (risk: {verdict.risk_score:.2f})")


class _CompletionsProxy:
    def __init__(self, completions: Any, firewall: Firewall) -> None:
        self._completions = completions
        self._firewall = firewall

    def create(self, *args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages", [])
        for msg in messages:
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

        response = self._completions.create(*args, **kwargs)

        if hasattr(response, "choices") and response.choices:
            for choice in response.choices:
                if hasattr(choice, "message") and hasattr(choice.message, "content"):
                    out_text = choice.message.content or ""
                    if out_text.strip():
                        out_verdict = self._firewall.scan_output(out_text)
                        if out_verdict.action == Action.BLOCK:
                            raise PromptInjectionBlocked(out_verdict)

        return response


class _ChatProxy:
    def __init__(self, chat: Any, firewall: Firewall) -> None:
        self._chat = chat
        self._firewall = firewall

    @property
    def completions(self) -> _CompletionsProxy:
        return _CompletionsProxy(self._chat.completions, self._firewall)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._chat, name)


class OpenAIGuard:
    """Wraps OpenAI / AzureOpenAI client to automatically scan request messages and output responses."""

    def __init__(self, client: Any, *, config: Any | None = None) -> None:
        self._client = client
        self._firewall = Firewall(config=config)

    @property
    def chat(self) -> _ChatProxy:
        return _ChatProxy(self._client.chat, self._firewall)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)
