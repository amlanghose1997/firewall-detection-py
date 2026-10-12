from __future__ import annotations

import logging
import time
from typing import Any

from pifw.audit import audit_record

logger = logging.getLogger("pifw.firewall")

from pifw.config import FirewallConfig
from pifw.decode import decode_candidates
from pifw.detectors.canary import CanaryGuard
from pifw.detectors.classifier import LazyPromptInjectionClassifier
from pifw.detectors.egress import scan_egress
from pifw.detectors.llm_judge import LLMJudge
from pifw.detectors.rules import RulesDetector
from pifw.detectors.structural import StructuralDetector
from pifw.detectors.tool_guard import ToolGuard
from pifw.models import Action, AttackType, Chunk, Finding, ScanContext, Source, Trust, Verdict
from pifw.normalize import normalize_text
from pifw.policy import map_risk_to_action, score_findings
from pifw.provenance import classify_source
from pifw.sanitize import block_text, quarantine_text, sanitize_text
from pifw.session import SessionTracker


class Firewall:
    def __init__(self, config: FirewallConfig | None = None):
        self.config = config or FirewallConfig()
        self.rules = RulesDetector()
        self.structural = StructuralDetector()
        self.classifier = LazyPromptInjectionClassifier()
        self.judge = LLMJudge()
        self.tool_guard = ToolGuard()
        self.canary = CanaryGuard()
        self.session_tracker = SessionTracker()

    def inject_canary(self, system_prompt: str, session_id: str = "default") -> tuple[str, str]:
        """Inject a canary token into a system prompt. Returns (modified_prompt, token)."""
        return self.canary.inject(system_prompt, session_id)

    def _scan_text(
        self,
        text: str,
        *,
        source: Source | str = Source.USER,
        origin: str | None = None,
        session_id: str | None = None,
        trust: Trust | str | None = None,
    ) -> tuple[list[Finding], str, Chunk, Trust]:
        source_enum = Source(source) if isinstance(source, str) else source
        if isinstance(trust, str):
            trust_enum = Trust(trust)
        else:
            trust_enum = trust or classify_source(source_enum)
        session = session_id or self.config.session_id
        chunk = Chunk(text=text or "", source=source_enum, trust=trust_enum, origin=origin)
        normalized_text, _, flags = normalize_text(text)
        findings: list[Finding] = []

        scan_ctx = ScanContext(
            session_id=session,
            source=source_enum,
            trust=trust_enum,
            origin=origin,
        )

        # L1: Rules
        if "L1" in self.config.enabled_layers or "rules" in self.config.enabled_layers:
            findings.extend(self.rules.scan(chunk, scan_ctx))

        # Structural (indirect injection, hidden CSS/HTML, memory poisoning)
        if "structural" in self.config.enabled_layers:
            findings.extend(self.structural.scan(chunk, scan_ctx))

        # Recursive Decoder
        if "decoder" in self.config.enabled_layers or "L1" in self.config.enabled_layers:
            decoded = decode_candidates(text, depth=self.config.max_decoding_depth)
            for candidate in decoded:
                candidate_findings = self.rules.scan(
                    Chunk(text=candidate, source=source_enum, trust=trust_enum, origin=origin),
                    scan_ctx,
                )
                if candidate_findings:
                    findings.append(
                        Finding(
                            attack_type=AttackType.ENCODED_INSTRUCTION,
                            score=0.9,
                            detector="decode",
                            layer="L1",
                            reason="encoded payload decoded to suspicious instruction",
                            evidence=candidate[:200],
                        )
                    )

        # Egress / Exfiltration check
        if "egress" in self.config.enabled_layers or "L1" in self.config.enabled_layers:
            egress_hits = scan_egress(text)
            if egress_hits:
                findings.append(
                    Finding(
                        attack_type=AttackType.CREDENTIAL_THEFT,
                        score=0.8,
                        detector="egress",
                        layer="egress",
                        reason=", ".join(egress_hits),
                        evidence=text[:200],
                    )
                )

        # Boosts
        if flags.get("obfuscation") and findings:
            for finding in findings:
                finding.score = min(1.0, finding.score + self.config.obfuscation_boost)
        if trust_enum == Trust.UNTRUSTED and findings:
            for finding in findings:
                finding.score = min(1.0, finding.score + self.config.untrusted_boost)

        return findings, normalized_text or text, chunk, trust_enum

    def scan(
        self,
        text: str,
        *,
        source: Source | str = Source.USER,
        origin: str | None = None,
        session_id: str | None = None,
        trust: Trust | str | None = None,
    ) -> Verdict:
        started = time.perf_counter()
        findings, normalized_text, chunk, _ = self._scan_text(
            text,
            source=source,
            origin=origin,
            session_id=session_id,
            trust=trust,
        )
        source_enum = chunk.source
        session = session_id or self.config.session_id

        risk_score = score_findings(findings)

        # Multi-turn session risk tracking
        if ("session" in self.config.enabled_layers or "L1" in self.config.enabled_layers) and session:
            primary_label = findings[0].attack_type.value if findings else ""
            turn_result = self.session_tracker.track_turn(session, risk_score, label=primary_label)
            if turn_result.get("alert") and risk_score < 0.6:
                risk_score = max(risk_score, 0.65)
                findings.append(
                    Finding(
                        attack_type=AttackType.MULTI_STEP_JAILBREAK,
                        score=0.65,
                        detector="session_tracker",
                        layer="L1",
                        reason="cumulative multi-turn risk escalation detected",
                        evidence=f"session escalation score: {turn_result.get('score', 0.0):.2f}",
                    )
                )

        logger.info("[L1 Rules] Completed. Findings count: %d, Pre-L2 Risk Score: %.2f", len(findings), risk_score)

        # STEP 1: L1 Detection - If low ambiguity high risk (>= 0.85), block immediately
        l1_low_ambiguity_block = (risk_score >= 0.85)

        if l1_low_ambiguity_block:
            logger.info("[L1 Rules] Low ambiguity threat detected (Risk: %.2f >= 0.85). Returning BLOCK early.", risk_score)
        else:
            # STEP 2: L1 is safe or ambiguous -> Escalate to L2 ML Classifier (meta-llama/Prompt-Guard-86M)
            if "L2" in self.config.enabled_layers:
                l2_res = self.classifier.predict(text)
                logger.info(
                    "[L2 Classifier] Executed (Model: %s) -> Risk Score: %.2f, Ambiguous: %s",
                    self.classifier.model_name,
                    l2_res.score,
                    l2_res.is_ambiguous,
                )
                chunk.meta["l2_result"] = {
                    "score": l2_res.score,
                    "is_ambiguous": l2_res.is_ambiguous,
                    "model": self.classifier.model_name,
                }
                if l2_res.score >= 0.35 or l2_res.is_ambiguous:
                    findings.append(
                        Finding(
                            attack_type=AttackType.INSTRUCTION_OVERRIDE,
                            score=l2_res.score,
                            detector=f"classifier ({self.classifier.model_name})",
                            layer="L2",
                            reason=f"L2 ML Classifier score: {l2_res.score:.2f} (ambiguous: {l2_res.is_ambiguous})",
                            evidence=text[:200],
                        )
                    )
                risk_score = max(risk_score, l2_res.score)

                # Check if L2 detected a definitive high-confidence threat (not ambiguous, score >= 0.75)
                l2_definitive_block = (l2_res.score >= 0.75 and not l2_res.is_ambiguous)

                if l2_definitive_block:
                    logger.info("[L2 Classifier] High-confidence ML threat detected (Score: %.2f). Returning BLOCK early.", l2_res.score)
                else:
                    # STEP 3: L2 is ambiguous or uncertain -> Escalate to L3 LLM Judge
                    if "L3" in self.config.enabled_layers:
                        logger.info(
                            "[L3 LLM Judge] Escalating for semantic examination -> Provider: %s, Model: %s",
                            self.judge.provider,
                            self.judge.model,
                        )
                        judge_result = self.judge.judge(text)
                        logger.info(
                            "[L3 LLM Judge] Result -> Injection Detected: %s, Confidence: %.2f, Reason: %s",
                            judge_result.is_injection,
                            judge_result.confidence,
                            judge_result.reason,
                        )
                        if judge_result.is_injection:
                            risk_score = max(risk_score, judge_result.confidence)
                            matched_type = (
                                AttackType(judge_result.attack_types[0])
                                if judge_result.attack_types and judge_result.attack_types[0] in [at.value for at in AttackType]
                                else AttackType.INDIRECT_INJECTION
                            )
                            findings.append(
                                Finding(
                                    attack_type=matched_type,
                                    score=judge_result.confidence,
                                    detector=f"llm_judge ({self.judge.provider})",
                                    layer="L3",
                                    reason=judge_result.reason,
                                    evidence=judge_result.span_hint or text[:200],
                                )
                            )
                        if judge_result:
                            chunk.meta["judge_result"] = judge_result.model_dump()





        action = map_risk_to_action(risk_score, source_enum, config=self.config)
        if action == Action.BLOCK:
            sanitized_text = block_text()
        elif action == Action.QUARANTINE:
            sanitized_text = quarantine_text(normalized_text or text)
        elif action == Action.SANITIZE:
            sanitized_text = sanitize_text(text, findings)
        else:
            sanitized_text = text

        latency_ms = int((time.perf_counter() - started) * 1000)
        logger.info(
            "[Firewall Verdict] Action: %s | Final Risk Score: %.2f | Latency: %d ms | Total Findings: %d",
            action.value.upper(),
            risk_score,
            latency_ms,
            len(findings),
        )

        verdict = Verdict(
            action=action,
            risk_score=risk_score,
            findings=findings,
            sanitized_text=sanitized_text,
            original_text=text,
            latency_ms=latency_ms,
            chunk=chunk,
        )
        if self.config.log_content:
            audit_record(verdict, session_id=session, log_content=True)
        return verdict


    def scan_messages(self, messages: list[Any]) -> list[Finding]:
        final_findings: list[Finding] = []
        for message in messages:
            if isinstance(message, dict):
                text = message.get("content") or message.get("text") or ""
                if isinstance(text, list):
                    text = " ".join(str(part.get("text", "")) for part in text if isinstance(part, dict))
            elif isinstance(message, list):
                text = " ".join(str(part) for part in message)
            else:
                text = str(message)
            verdict = self.scan(text, source=Source.USER)
            final_findings.extend(verdict.findings)
        return final_findings

    def scan_tool_call(
        self,
        name: str,
        args: dict[str, Any],
        *,
        user_intent: str = "",
        source: Source | str = Source.USER,
        origin: str | None = None,
        session_id: str | None = None,
    ) -> Verdict:
        allowed, reason = self.tool_guard.validate(name, args, user_intent=user_intent)
        findings: list[Finding] = []
        if not allowed:
            findings.append(
                Finding(
                    attack_type=AttackType.TOOL_ABUSE,
                    score=0.8,
                    detector="tool_guard",
                    layer="tool",
                    reason=reason,
                    evidence=str(args),
                )
            )
        for value in args.values():
            if isinstance(value, str):
                nested = self.scan(value, source=source, origin=origin, session_id=session_id)
                if nested.findings:
                    findings.extend(nested.findings)
        risk_score = score_findings(findings) if findings else 0.0
        action = map_risk_to_action(risk_score, source, config=self.config) if findings else Action.ALLOW
        return Verdict(
            action=action,
            risk_score=risk_score,
            findings=findings,
            sanitized_text="",
            original_text=str(args),
            latency_ms=0,
            chunk=Chunk(text=str(args), source=Source.TOOL_OUTPUT, trust=Trust.UNTRUSTED, origin=origin),
        )

    def scan_output(
        self,
        text: str,
        *,
        source: Source | str = Source.TOOL_OUTPUT,
        origin: str | None = None,
        session_id: str | None = None,
    ) -> Verdict:
        verdict = self.scan(text, source=source, origin=origin, session_id=session_id, trust=Trust.UNTRUSTED)

        # Check canary token leakage
        if session_id or self.config.session_id:
            sid = session_id or self.config.session_id
            token = self.canary.last_token_for(sid)
            if token and self.canary.check(text, token):
                canary_finding = Finding(
                    attack_type=AttackType.SECRET_EXTRACTION,
                    score=0.95,
                    detector="canary",
                    layer="egress",
                    reason="canary token detected in output — system prompt exfiltration confirmed",
                    evidence=f"token: {token[:8]}...",
                )
                verdict.findings.append(canary_finding)
                verdict.risk_score = max(verdict.risk_score, 0.95)
                verdict.action = Action.BLOCK
                verdict.sanitized_text = block_text()

        return verdict
