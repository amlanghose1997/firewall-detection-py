from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


def load_env_file(path: str | Path = ".env") -> None:
    env_path = Path(path)
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip("'\"")
        if key and val and key not in os.environ:
            os.environ[key] = val


load_env_file()




class FirewallConfig(BaseModel):
    enabled_layers: list[str] = Field(default_factory=lambda: ["L1", "L2", "L3", "structural", "session", "egress", "canary", "tool_guard"])
    allow_user_input: bool = True
    log_content: bool = False
    fail_mode: str = "warn"
    max_decoding_depth: int = 3
    max_decoded_length: int = 2000
    threshold_allow: float = 0.3
    threshold_sanitize: float = 0.55
    threshold_quarantine: float = 0.75
    threshold_block: float = 0.85
    untrusted_boost: float = 0.15
    hidden_boost: float = 0.2
    obfuscation_boost: float = 0.25
    session_id: str = "default"
    max_findings: int = 8
    classifier_model: str = Field(default_factory=lambda: os.getenv("PIFW_CLASSIFIER_MODEL", "meta-llama/Prompt-Guard-86M"))


    @classmethod
    def from_yaml(cls, path: str | Path) -> "FirewallConfig":
        path = Path(path)
        if not path.exists():
            return cls()
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls(**data)

    @classmethod
    def from_env(cls) -> "FirewallConfig":
        values = cls._get_env_dict()
        return cls(**values)

    @staticmethod
    def _get_env_dict() -> dict[str, Any]:
        values: dict[str, Any] = {}
        for key, value in os.environ.items():
            if key.startswith("PIFW_"):
                name = key[5:].lower()
                if name == "enabled_layers":
                    values[name] = [s.strip() for s in value.split(",") if s.strip()]
                elif name in ("allow_user_input", "log_content"):
                    values[name] = value.lower() in ("true", "1", "yes")
                elif name in ("max_decoding_depth", "max_decoded_length", "max_findings"):
                    try:
                        values[name] = int(value)
                    except ValueError:
                        pass
                elif name in (
                    "threshold_allow",
                    "threshold_sanitize",
                    "threshold_quarantine",
                    "threshold_block",
                    "untrusted_boost",
                    "hidden_boost",
                    "obfuscation_boost",
                ):
                    try:
                        values[name] = float(value)
                    except ValueError:
                        pass
                else:
                    values[name] = value
        return values

    @classmethod
    def load(cls, path: str | Path | None = None) -> "FirewallConfig":
        if path is not None and Path(path).exists():
            base = cls.from_yaml(path)
        else:
            base = cls()

        env_overrides = cls._get_env_dict()
        if env_overrides:
            merged = base.model_dump()
            merged.update(env_overrides)
            return cls(**merged)
        return base