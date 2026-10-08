
from __future__ import annotations

from typing import Any


class AutoGenHook:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs

    def transform(self, message: Any) -> Any:
        return message
