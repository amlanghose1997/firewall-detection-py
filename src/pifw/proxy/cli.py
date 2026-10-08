
from __future__ import annotations

import argparse


def main() -> None:
    try:
        import uvicorn
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError("Install pifw[proxy] to use the proxy CLI.") from exc

    parser = argparse.ArgumentParser(description="Run the pifw OpenAI-compatible proxy")
    parser.add_argument("--config", default=None)
    parser.add_argument("--upstream", default="https://api.openai.com/v1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    print(f"pifw proxy ready on :{args.port} with upstream {args.upstream}")
    uvicorn.run("pifw.proxy.app:app", host="0.0.0.0", port=args.port, reload=False)
