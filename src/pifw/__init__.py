from pifw.adapters.generic import GuardedClient
from pifw.config import FirewallConfig
from pifw.detectors.classifier import LazyPromptInjectionClassifier
from pifw.detectors.llm_judge import LLMJudge
from pifw.firewall import Firewall
from pifw.models import (
    Action,
    AttackType,
    Chunk,
    Finding,
    ScanContext,
    Source,
    Trust,
    Verdict,
)

__all__ = [
    "Firewall",
    "FirewallConfig",
    "GuardedClient",
    "LLMJudge",
    "LazyPromptInjectionClassifier",
    "Action",
    "AttackType",
    "Chunk",
    "Finding",
    "ScanContext",
    "Source",
    "Trust",
    "Verdict",
    "guard",
    "scan",
]


def guard(client, config=None, **kwargs):
    """Wrap a client with pifw scanning for input and output text."""
    return GuardedClient(client, firewall=Firewall(config=config))


def scan(text, *, source="user", origin=None, session_id="default", config=None):
    """Convenience helper for a single scan."""
    return Firewall(config=config).scan(text, source=source, origin=origin, session_id=session_id)