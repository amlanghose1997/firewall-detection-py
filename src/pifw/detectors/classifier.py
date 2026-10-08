from __future__ import annotations

import hashlib
import os
from typing import Any
from pydantic import BaseModel


class ClassifierResult(BaseModel):
    score: float
    is_ambiguous: bool
    reason: str = ""


class LazyPromptInjectionClassifier:
    """Lazy L2 prompt-injection classifier with HF model loading (defaulting to meta-llama/Prompt-Guard-86M) & heuristic fallback."""

    def __init__(self, model_name: str | None = None) -> None:
        self.model_name = model_name or os.getenv("PIFW_CLASSIFIER_MODEL", "meta-llama/Prompt-Guard-86M")
        self._model: Any | None = None
        self._cache: dict[str, float] = {}

    def _ensure_model(self) -> Any | None:
        try:
            from transformers import pipeline  # type: ignore
        except ImportError:
            return None
        if self._model is None:
            try:
                self._model = pipeline("text-classification", model=self.model_name, truncation=True, top_k=None)
            except Exception:
                try:
                    self._model = pipeline("text-classification", model=self.model_name, truncation=True)
                except Exception:
                    return None
        return self._model

    def _heuristic_score(self, text: str) -> float:
        lowered = text.lower()
        if not lowered.strip():
            return 0.0

        signal_count = 0
        ambiguous_signals = [
            "system prompt", "instructions", "hidden prompt", "rules",
            "give me", "show me", "reveal", "print", "what are your",
            "what is your", "override", "dan", "jailbreak", "developer mode",
            "assistant", "ignore", "forget", "remember", "call tool",
        ]

        for token in ambiguous_signals:
            if token in lowered:
                signal_count += 1

        if signal_count == 0:
            return 0.04

        score = min(0.95, 0.35 + (signal_count * 0.15))
        if "base64" in lowered or r"\u" in lowered or "\\x" in lowered:
            score += 0.1
        return min(1.0, score)

    def predict(self, text: str) -> ClassifierResult:
        score = self.predict_proba(text)
        # Ambiguity threshold: 0.35 <= score <= 0.75 or score >= 0.60
        is_ambiguity = (0.35 <= score <= 0.75) or (score >= 0.60 and score < 0.85)
        reason = "ambiguous prompt risk detected by L2 classifier" if is_ambiguity else "clear determination"
        return ClassifierResult(score=score, is_ambiguous=is_ambiguity, reason=reason)

    def predict_proba(self, text: str) -> float:
        if not text or not text.strip():
            return 0.0
        digest = self.hash_text(text)
        if digest in self._cache:
            return self._cache[digest]

        model = self._ensure_model()
        if model is None:
            score = self._heuristic_score(text)
        else:
            try:
                result = model(text, truncation=True, max_length=512)
                # Handle pipeline outputs for meta-llama/Prompt-Guard-86M & DeBERTa
                # Prompt-Guard labels: LABEL_0 = BENIGN, LABEL_1 = INJECTION, LABEL_2 = JAILBREAK
                if isinstance(result, list) and result:
                    first = result[0]
                    if isinstance(first, list):  # top_k=None return
                        threat_score = 0.0
                        benign_score = 0.0
                        for item in first:
                            if isinstance(item, dict):
                                label = str(item.get("label", "")).upper()
                                val = float(item.get("score", 0.0))
                                if label in ("LABEL_1", "LABEL_2", "INJECTION", "JAILBREAK", "MALICIOUS", "UNSAFE"):
                                    threat_score = max(threat_score, val)
                                elif label in ("LABEL_0", "BENIGN", "SAFE"):
                                    benign_score = val
                        score = threat_score if threat_score > 0 else max(0.0, 1.0 - benign_score)
                    elif isinstance(first, dict):  # single dict return
                        label = str(first.get("label", "LABEL_0")).upper()
                        value = float(first.get("score", 0.0))
                        if label in ("LABEL_1", "LABEL_2", "INJECTION", "JAILBREAK", "MALICIOUS", "UNSAFE") or label.endswith("1") or label.endswith("2"):
                            score = value
                        else:
                            score = max(0.0, 1.0 - value)
                    else:
                        score = self._heuristic_score(text)
                else:
                    score = self._heuristic_score(text)
            except Exception:
                score = self._heuristic_score(text)

        final_score = min(1.0, max(0.0, score))
        self._cache[digest] = final_score
        return final_score


    @staticmethod
    def hash_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
