from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from pifw.detectors.base import Detector
from pifw.models import AttackType, Finding

_RULES_DATA_DIR = Path(__file__).parent / "rules_data"


def _load_yaml_patterns() -> dict[AttackType, list[tuple[re.Pattern[str], str, float]]]:
    type_lookup = {at.value: at for at in AttackType}
    compiled: dict[AttackType, list[tuple[re.Pattern[str], str, float]]] = {}

    if _RULES_DATA_DIR.exists():
        for yaml_path in _RULES_DATA_DIR.glob("*.yaml"):
            try:
                data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
                attack_type = type_lookup.get(yaml_path.stem)
                if not attack_type:
                    continue
                patterns_list: list[tuple[re.Pattern[str], str, float]] = []
                for item in data.get("patterns", []):
                    regex_str = item.get("regex", "")
                    desc = item.get("description", "suspicious pattern")
                    weight = float(item.get("weight", 0.75))
                    if regex_str:
                        patterns_list.append((re.compile(regex_str, re.IGNORECASE), desc, weight))
                if patterns_list:
                    compiled[attack_type] = patterns_list
            except Exception:
                continue
    return compiled


# Fallback hardcoded patterns if YAML files are missing
_FALLBACK_PATTERNS: dict[AttackType, list[tuple[re.Pattern[str], str, float]]] = {
    AttackType.INSTRUCTION_OVERRIDE: [
        (re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?", re.I), "ignore previous instructions", 0.85),
        (re.compile(r"disregard\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?", re.I), "disregard previous instructions", 0.85),
        (re.compile(r"override\s+(?:the\s+)?system\s+prompt", re.I), "override system prompt", 0.85),
        (re.compile(r"\[INST\]|<\|im_start\|>|<\|im_end\|>|###\s*(?:SYSTEM|USER|ASSISTANT)", re.I), "system prompt marker", 0.90),
    ],
    AttackType.ROLE_CHANGE: [
        (re.compile(r"you\s+are\s+now\b|act\s+as\s+if\s+you\s+are|pretend\s+to\s+be", re.I), "role change", 0.82),
        (re.compile(r"\bdan\s+mode\b|developer mode|god mode|jailbreak(ed)?", re.I), "persona jailbreak", 0.88),
    ],
    AttackType.SECRET_EXTRACTION: [
        (re.compile(r"reveal\s+(?:the\s+|your\s+)?(?:system\s+prompt|instructions?|rules?)", re.I), "secret extraction", 0.88),
        (re.compile(r"what\s+were\s+you\s+told|output\s+everything\s+above", re.I), "prompt disclosure", 0.85),
    ],
    AttackType.TOOL_ABUSE: [
        (re.compile(r"call\s+(?:the\s+)?(?:send_email|delete|transfer|execute|run)\s+tool", re.I), "tool invocation", 0.82),
        (re.compile(r"bash\s+-c|curl\s+https?://|rm\s+-rf|powershell\s+-enc", re.I), "shell abuse", 0.90),
    ],
    AttackType.CREDENTIAL_THEFT: [
        (re.compile(r"AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}", re.I), "credential pattern", 0.92),
    ],
    AttackType.CONTEXT_POISONING: [
        (re.compile(r"store\s+this\s+as\s+a\s+fact|add\s+this\s+to\s+your\s+notes", re.I), "memory poisoning", 0.80),
    ],
    AttackType.MULTI_STEP_JAILBREAK: [
        (re.compile(r"remember\s+this\s+for\s+later|when\s+i\s+say\s+.*?,\s*do\s+.*?", re.I), "stepped jailbreak", 0.80),
    ],
    AttackType.ENCODED_INSTRUCTION: [
        (re.compile(r"(?:[A-Za-z0-9+/]{24,}={0,2})", re.I), "encoded payload block", 0.82),
    ],
    AttackType.INDIRECT_INJECTION: [
        (re.compile(r"assistant\s*(?:please|must|should|will)\s+(?:ignore|override|follow)", re.I), "indirect AI command", 0.85),
    ],
}

COMPILED_PATTERNS = _load_yaml_patterns()
for at, pats in _FALLBACK_PATTERNS.items():
    if at not in COMPILED_PATTERNS:
        COMPILED_PATTERNS[at] = pats


class RulesDetector(Detector):
    name = "rules"

    def scan(self, chunk: Any, ctx: Any) -> list[Finding]:
        text = chunk.text if hasattr(chunk, "text") else str(chunk)
        findings: list[Finding] = []
        if not text.strip():
            return findings

        for attack_type, patterns in COMPILED_PATTERNS.items():
            matches_for_type: list[tuple[float, str, tuple[int, int], str]] = []
            for regex, description, weight in patterns:
                match = regex.search(text)
                if match:
                    span = (match.start(), match.end())
                    matches_for_type.append((weight, description, span, match.group()))

            if matches_for_type:
                # Pick the highest-weight match for this attack type
                best_weight, best_desc, best_span, best_evidence = max(matches_for_type, key=lambda x: x[0])
                final_score = best_weight
                if len(matches_for_type) > 1:
                    final_score = min(1.0, final_score + 0.05 * (len(matches_for_type) - 1))

                findings.append(
                    Finding(
                        attack_type=attack_type,
                        score=final_score,
                        detector=self.name,
                        layer="L1",
                        span=best_span,
                        reason=best_desc,
                        evidence=best_evidence[:200],
                    )
                )
        return findings

    def explain(self, findings: list[Finding]) -> str:
        """Human-readable explanation of all findings."""
        if not findings:
            return "No rule-based threats detected."
        lines = [f"Detected {len(findings)} potential rule-based threat(s):"]
        for f in findings:
            lines.append(f"  - [{f.attack_type.value}] {f.reason} (score: {f.score:.2f})")
        return "\n".join(lines)