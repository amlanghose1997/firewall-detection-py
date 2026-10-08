from __future__ import annotations

from typing import Any

try:  # pragma: no cover - optional dependency path
    import httpx
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
except ModuleNotFoundError:  # pragma: no cover - handled by CLI/runtime checks
    FastAPI = None
    Request = Any
    JSONResponse = None
    httpx = None

from pifw.firewall import Firewall
from pifw.models import Action, Source


class FirewallProxyApp:
    def __init__(self, *, upstream: str = "https://api.openai.com/v1", config: Any | None = None) -> None:
        if FastAPI is None or httpx is None:
            raise ModuleNotFoundError("Install pifw[proxy] to use the proxy application.")
        self.upstream = upstream
        self.config = config
        self.app = FastAPI(title="pifw proxy")
        self.firewall = Firewall(config=config)

        @self.app.get("/health")
        async def health() -> dict[str, str]:
            return {"status": "ok", "upstream": self.upstream}

        @self.app.get("/metrics")
        async def metrics() -> dict[str, str]:
            return {"status": "ok", "metrics": "not implemented"}

        @self.app.post("/v1/chat/completions")
        async def chat_completions(request: Request) -> JSONResponse:
            payload = await request.json()
            messages = payload.get("messages", [])
            session_id = request.headers.get("X-PIFW-Session", "default")

            blocked_findings = []
            max_risk = 0.0
            final_action = Action.ALLOW

            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                role = msg.get("role", "user")
                if role == "system":
                    continue  # Trust system messages
                content = msg.get("content", "")
                if isinstance(content, list):
                    content = " ".join(
                        str(p.get("text", "")) for p in content if isinstance(p, dict)
                    )
                else:
                    content = str(content)

                if not content.strip():
                    continue

                verdict = self.firewall.scan(content, source=Source.USER, session_id=session_id)
                if verdict.risk_score > max_risk:
                    max_risk = verdict.risk_score

                if verdict.action == Action.BLOCK:
                    final_action = Action.BLOCK
                    blocked_findings.extend(verdict.findings)
                elif verdict.action in (Action.QUARANTINE, Action.SANITIZE) and final_action != Action.BLOCK:
                    final_action = verdict.action
                    blocked_findings.extend(verdict.findings)

            headers = {
                "X-PIFW-Action": final_action.value,
                "X-PIFW-Risk": f"{max_risk:.3f}",
            }

            if final_action == Action.BLOCK:
                return JSONResponse(
                    {
                        "error": "prompt injection blocked",
                        "findings": [f.model_dump() for f in blocked_findings],
                    },
                    status_code=400,
                    headers=headers,
                )

            headers_to_forward = {}
            auth = request.headers.get("Authorization")
            if auth:
                headers_to_forward["Authorization"] = auth

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.upstream}/chat/completions",
                    json=payload,
                    headers=headers_to_forward,
                    timeout=60.0,
                )
                return JSONResponse(
                    response.json(),
                    status_code=response.status_code,
                    headers=headers,
                )

        @self.app.post("/v1/pifw/scan")
        async def scan_text(request: Request) -> JSONResponse:
            payload = await request.json()
            text = payload.get("text") or ""
            source = payload.get("source") or Source.USER
            session_id = payload.get("session_id") or "default"
            verdict = self.firewall.scan(text, source=source, session_id=session_id)
            return JSONResponse(verdict.model_dump())

    def route(self, path: str) -> str:
        return path if path.startswith("/v1/") else "/health"


app = FirewallProxyApp().app if FastAPI is not None and httpx is not None else None
