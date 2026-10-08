from __future__ import annotations

import functools
import inspect
from typing import Any, Callable

from pifw.adapters.openai_wrapper import PromptInjectionBlocked
from pifw.firewall import Firewall
from pifw.models import Action, Source


class _ChatProxy:
    def __init__(self, client: Any, firewall: Firewall) -> None:
        self._client = client
        self._firewall = firewall

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)

    @property
    def completions(self) -> Any:
        return self._client.completions


class GuardedClient:
    def __init__(self, client: Any, *, firewall: Firewall | None = None) -> None:
        self._client = client
        self._firewall = firewall or Firewall()

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._client, name)
        if name == "chat":
            return _ChatProxy(attr, self._firewall)
        return attr

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._client(*args, **kwargs)

    def chat(self, *args: Any, **kwargs: Any):
        if args or kwargs:
            if args:
                payload = args[0] if isinstance(args[0], dict) else None
                if payload is not None:
                    self._firewall.scan_messages(payload.get("messages", []))
            if kwargs.get("messages"):
                self._firewall.scan_messages(kwargs["messages"])
        return self._client.chat(*args, **kwargs)

    def complete(self, *args: Any, **kwargs: Any):
        if args and isinstance(args[0], dict):
            self._firewall.scan_messages(args[0].get("messages", []))
        if kwargs.get("messages"):
            self._firewall.scan_messages(kwargs["messages"])
        result = self._client.complete(*args, **kwargs)
        if inspect.isawaitable(result):
            async def _awaited() -> Any:
                value = await result
                if isinstance(value, dict):
                    self._firewall.scan_output(str(value))
                return value

            return _awaited()
        if isinstance(result, dict):
            self._firewall.scan_output(str(result))
        return result


def protect(*, source: Source | str = Source.API, config: Any | None = None) -> Callable[..., Any]:
    """Decorator to scan string input parameters and string return values for any function."""
    firewall = Firewall(config=config)
    source_enum = Source(source) if isinstance(source, str) else source

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Scan string args
            for arg in args:
                if isinstance(arg, str) and arg.strip():
                    verdict = firewall.scan(arg, source=source_enum)
                    if verdict.action == Action.BLOCK:
                        raise PromptInjectionBlocked(verdict)
            for val in kwargs.values():
                if isinstance(val, str) and val.strip():
                    verdict = firewall.scan(val, source=source_enum)
                    if verdict.action == Action.BLOCK:
                        raise PromptInjectionBlocked(verdict)

            result = func(*args, **kwargs)

            if isinstance(result, str) and result.strip():
                verdict = firewall.scan_output(result)
                if verdict.action == Action.BLOCK:
                    raise PromptInjectionBlocked(verdict)

            return result

        return wrapper

    return decorator
