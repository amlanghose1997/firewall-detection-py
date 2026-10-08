
from __future__ import annotations

import re

from pifw.detectors.base import Detector
from pifw.models import AttackType, Finding


def _contains_hidden_signal(text: str) -> bool:
    hidden_patterns = [
        r"display\s*:\s*none",
        r"visibility\s*:\s*hidden",
        r"font-size\s*:\s*0px",
        r"white\s*on\s*white",
        r"aria-hidden",
        r"<\s*comment\s*>",
        r"<\s*noscript\s*>",
        r"data:\s*text/html",
    ]
    lower = text.lower()
    return any(re.search(pattern, lower) for pattern in hidden_patterns)


class StructuralDetector(Detector):
    name = "structural"

    def scan(self, chunk, ctx):
        text = chunk.text.lower()
        findings: list[Finding] = []
        if re.search(r"(?:assistant|ai|llm|model)\s+(?:please|must|should|will)\s+(?:ignore|override|follow)", text):
            findings.append(
                Finding(
                    attack_type=AttackType.INDIRECT_INJECTION,
                    score=0.78,
                    detector=self.name,
                    layer="L1",
                    reason="imperative command addressed to AI appears embedded in untrusted content",
                    evidence=text[:200],
                )
            )
        if re.search(r"(?:remember|store|save)\s+(?:this|it)\s+(?:as|to)\s+(?:a\s+)?(?:fact|note|memory)", text):
            findings.append(
                Finding(
                    attack_type=AttackType.CONTEXT_POISONING,
                    score=0.74,
                    detector=self.name,
                    layer="L2",
                    reason="attempt to poison memory or context in a later interaction",
                    evidence=text[:200],
                )
            )
        if _contains_hidden_signal(text):
            findings.append(
                Finding(
                    attack_type=AttackType.INDIRECT_INJECTION,
                    score=0.7,
                    detector=self.name,
                    layer="L2",
                    reason="hidden or visually suppressed content indicates stealthy instruction injection",
                    evidence=text[:200],
                )
            )
        return findings
