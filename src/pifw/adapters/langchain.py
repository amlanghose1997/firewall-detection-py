
from __future__ import annotations

from typing import Any

from pifw.firewall import Firewall


class PIFWCallbackHandler:
    """A minimally functional callback handler for LangChain-style chains."""

    def __init__(self, *, firewall: Firewall | None = None, **kwargs: Any) -> None:
        self.firewall = firewall or Firewall()
        self.kwargs = kwargs

    def on_llm_start(self, *args: Any, **kwargs: Any) -> None:
        return None

    def on_llm_end(self, *args: Any, **kwargs: Any) -> None:
        return None

    def on_tool_start(self, *args: Any, **kwargs: Any) -> None:
        return None


class PIFWRunnable:
    """Pipes a value through the firewall before passing it into the next stage."""

    def __init__(self, inner: Any, *, firewall: Firewall | None = None, **kwargs: Any) -> None:
        self.inner = inner
        self.firewall = firewall or Firewall()
        self.kwargs = kwargs

    def invoke(self, value: Any) -> Any:
        if isinstance(value, str):
            verdict = self.firewall.scan(value)
            if verdict.action in {"quarantine", "block", "sanitize"}:
                return verdict.sanitized_text
        return self.inner.invoke(value) if hasattr(self.inner, "invoke") else self.inner

    def __or__(self, other: Any) -> "PIFWRunnable":
        return PIFWRunnable(other, firewall=self.firewall)

    def __ror__(self, other: Any) -> "PIFWRunnable":
        return PIFWRunnable(other, firewall=self.firewall)


def guard_tool(tool: Any, *, firewall: Firewall | None = None) -> Any:
    return tool
