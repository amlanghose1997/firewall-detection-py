from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from pifw.models import Verdict

logger = logging.getLogger("pifw.audit")


def audit_record(
    verdict: Verdict,
    *,
    session_id: str = "default",
    log_content: bool = False,
    audit_file: str | Path | None = None,
) -> dict:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session": session_id,
        "action": verdict.action.value,
        "risk_score": verdict.risk_score,
        "findings": [
            {
                "attack_type": f.attack_type.value,
                "score": f.score,
                "reason": f.reason,
                "detector": f.detector,
                "layer": f.layer,
            }
            for f in verdict.findings
        ],
        "content_hash": hashlib.sha256(
            verdict.original_text.encode("utf-8")
        ).hexdigest()[:16],
        "latency_ms": verdict.latency_ms,
    }
    if log_content:
        payload["original_text"] = verdict.original_text

    logger.info(json.dumps(payload))

    if audit_file:
        try:
            audit_path = Path(audit_file)
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            with open(audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload) + "\n")
        except Exception:
            pass

    return payload