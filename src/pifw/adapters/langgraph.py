
from __future__ import annotations

from typing import Any


def firewall_node(*, config: Any | None = None) -> Any:
    return {"kind": "firewall-node", "config": config}


def firewall_router(*args: Any, **kwargs: Any) -> str:
    return "blocked" if args else "safe"
