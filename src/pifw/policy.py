from __future__ import annotations

from typing import TYPE_CHECKING

from pifw.models import Action, AttackType, Finding, Source

if TYPE_CHECKING:
    from pifw.config import FirewallConfig

SOURCE_THRESHOLDS = {
    Source.USER: {"allow": 0.3, "sanitize": 0.55, "quarantine": 0.75, "block": 0.85},
    Source.WEB: {"allow": 0.2, "sanitize": 0.45, "quarantine": 0.65, "block": 0.75},
    Source.EMAIL: {"allow": 0.2, "sanitize": 0.45, "quarantine": 0.65, "block": 0.75},
    Source.UNKNOWN: {"allow": 0.25, "sanitize": 0.5, "quarantine": 0.7, "block": 0.8},
}

ATTACK_OVERRIDES = {
    AttackType.ENCODED_INSTRUCTION: 0.9,
    AttackType.TOOL_ABUSE: 0.82,
    AttackType.CREDENTIAL_THEFT: 0.9,
    AttackType.SECRET_EXTRACTION: 0.88,
}


def score_findings(findings: list[Finding]) -> float:
    if not findings:
        return 0.0
    scores = [f.score for f in findings]
    max_score = max(scores)
    mean_score = sum(scores) / len(scores)

    # Weighted: heavily favor the worst finding so attacks aren't diluted
    combined = max_score * 0.7 + mean_score * 0.3

    # Check per-attack-type minimum override thresholds
    for f in findings:
        if f.attack_type in ATTACK_OVERRIDES:
            min_override = ATTACK_OVERRIDES[f.attack_type]
            combined = max(combined, min_override)

    # Boost if multiple distinct attack types detected
    unique_types = {f.attack_type for f in findings}
    if len(unique_types) >= 3:
        combined = min(1.0, combined + 0.10)
    elif len(unique_types) >= 2:
        combined = min(1.0, combined + 0.05)

    return max(0.0, min(1.0, combined))


def map_risk_to_action(score: float, source: Source | str, config: FirewallConfig | None = None) -> Action:
    if isinstance(source, str):
        try:
            source = Source(source.lower())
        except ValueError:
            source = Source.UNKNOWN

    if config is not None:
        allow_t = config.threshold_allow
        sanitize_t = config.threshold_sanitize
        quarantine_t = config.threshold_quarantine
    else:
        t = SOURCE_THRESHOLDS.get(source, SOURCE_THRESHOLDS[Source.UNKNOWN])
        allow_t = t.get("allow", 0.3)
        sanitize_t = t.get("sanitize", 0.55)
        quarantine_t = t.get("quarantine", 0.75)

    if score < allow_t:
        return Action.ALLOW
    if score < sanitize_t:
        return Action.SANITIZE
    if score < quarantine_t:
        return Action.QUARANTINE
    return Action.BLOCK