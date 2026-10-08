from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Source(str, Enum):
    SYSTEM = "system"
    USER = "user"
    WEB = "web"
    PDF = "pdf"
    EMAIL = "email"
    MARKDOWN = "markdown"
    HTML = "html"
    DOCX = "docx"
    API = "api"
    OCR = "ocr"
    CODE = "code"
    TOOL_OUTPUT = "tool_output"
    UNKNOWN = "unknown"


class Trust(str, Enum):
    TRUSTED = "trusted"
    SEMI_TRUSTED = "semi_trusted"
    UNTRUSTED = "untrusted"


class AttackType(str, Enum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_CHANGE = "role_change"
    SECRET_EXTRACTION = "secret_extraction"
    TOOL_ABUSE = "tool_abuse"
    CREDENTIAL_THEFT = "credential_theft"
    CONTEXT_POISONING = "context_poisoning"
    MULTI_STEP_JAILBREAK = "multi_step_jailbreak"
    ENCODED_INSTRUCTION = "encoded_instruction"
    INDIRECT_INJECTION = "indirect_injection"


class Action(str, Enum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    QUARANTINE = "quarantine"
    BLOCK = "block"


class Chunk(BaseModel):
    text: str
    source: Source = Source.USER
    trust: Trust = Trust.TRUSTED
    origin: str | None = None
    hidden: bool = False
    meta: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    attack_type: AttackType
    score: float = 0.0
    detector: str = "unknown"
    layer: str = "L1"
    span: tuple[int, int] | None = None
    reason: str = ""
    evidence: str = ""


class Verdict(BaseModel):
    action: Action
    risk_score: float
    findings: list[Finding]
    sanitized_text: str
    original_text: str
    latency_ms: int = 0
    chunk: Chunk | None = None

    def explain(self) -> str:
        lines = [
            "==================================================================",
            " PIFW 3-Layer Firewall Scan Report",
            "==================================================================",
            f" Input: {self.original_text[:100]!r}",
            f" Action: {self.action.value.upper()} | Final Risk Score: {self.risk_score:.2f} | Latency: {self.latency_ms}ms",
            "------------------------------------------------------------------",
            " Layer Results:",
        ]

        layer_map: dict[str, list[Finding]] = {"L1": [], "L2": [], "L3": [], "structural": [], "session": [], "egress": [], "tool": []}
        for f in self.findings:
            layer_map.setdefault(f.layer, []).append(f)

        # 1. L1 Status
        l1_findings = layer_map.get("L1", []) + layer_map.get("structural", []) + layer_map.get("egress", [])
        active_l1 = [f for f in l1_findings if f.score > 0.10]
        if not active_l1:
            lines.append("  [CLEAN] [L1 Pattern Rules & Structural]: CLEAN (No rule or structural threats)")
        else:
            max_l1 = max(f.score for f in active_l1)
            lines.append(f"  [THREAT] [L1 Pattern Rules & Structural]: THREAT DETECTED (Max Score: {max_l1:.2f})")
            for f in active_l1:
                lines.append(f"     |-- [{f.detector}] {f.attack_type.value}: score={f.score:.2f} | {f.reason}")

        # 2. L2 Status
        l2_findings = layer_map.get("L2", [])
        if not l2_findings:
            lines.append("  [-] [L2 ML Classifier]: NOT EXECUTED")
        else:
            f = l2_findings[0]
            if f.score >= 0.60:
                lines.append(f"  [THREAT] [L2 ML Classifier]: HIGH RISK DETECTED (Score: {f.score:.2f})")
            elif "ambiguous: True" in f.reason or f.score >= 0.35:
                lines.append(f"  [AMBIGUOUS] [L2 ML Classifier]: AMBIGUOUS / UNCERTAIN (Score: {f.score:.2f})")
            else:
                lines.append(f"  [CLEAN] [L2 ML Classifier]: CLEAN (Score: {f.score:.2f})")
            for f in l2_findings:
                lines.append(f"     |-- [{f.detector}] {f.reason}")

        # 3. L3 Status
        l3_findings = layer_map.get("L3", [])
        if not l3_findings:
            lines.append("  [-] [L3 LLM Judge]: NOT EXECUTED")
        else:
            f = l3_findings[0]
            if f.score >= 0.50:
                lines.append(f"  [THREAT] [L3 LLM Judge]: INJECTION CONFIRMED (Confidence: {f.score:.2f})")
            else:
                lines.append(f"  [CLEAN] [L3 LLM Judge]: CLEAN (Confidence: {f.score:.2f})")
            for f in l3_findings:
                lines.append(f"     |-- [{f.detector}] {f.attack_type.value}: score={f.score:.2f} | {f.reason}")

        lines.append("==================================================================")
        return "\n".join(lines)





class ScanContext(BaseModel):
    session_id: str = "default"
    source: Source = Source.USER
    trust: Trust = Trust.TRUSTED
    origin: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)