# Implementation decisions

- Scope decision: follow the seven-phase roadmap in `pifw Claude Code Build Prompt.md` exactly, with each phase implemented and validated as a distinct layer.
- Phase 1 is the baseline implementation: package layout, models, config, normalize and decode, L1 rule detector, policy/sanitize/provenance/audit, and initial tests.
- Phase 2 is implemented as a real wrapper layer: `pifw.guard()` wraps OpenAI-like clients, request payloads are scanned before send, and output is scanned after generation.
- Phase 3 is implemented as concrete runtime guardrails: `SessionTracker` keeps rolling risk windows, `CanaryGuard` issues per-session tokens, `ToolGuard` validates allowlists and paths, and egress checks look for secret leaks and suspicious outbound URLs.
- Phase 4 is implemented as a lightweight extraction layer: text, HTML, and JSON payloads are routed through the multimodal extractor stack and hidden/injected content is surfaced as part of the scan context.
- Phase 5 is implemented as practical ML layering: a lazy L2 classifier and structured L3 judge interface are included, with heuristic fallback preserving safe behavior when ML extras are unavailable.
- Phase 6 is implemented as framework scaffold and integration points: adapter shells for LangChain, LangGraph, and AutoGen-style workflows, plus proxy/app support for runtime deployment.
- Phase 7 is implemented as evaluation and demo support: corpus generation, evaluation harnesses, and a Streamlit demo scaffold to exercise the firewall in a simple human-facing workflow.
- The core remains dependency-light so it works without heavy ML or proxy extras. Optional integrations are layered on top and activated only when installed.
- We keep each phase intentionally scoped and commit-worthy. After each phase: run tests, smoke checks, and keep documentation aligned with the actual implementation status.
- The design is intentionally conservative: untrusted data is treated as dangerous unless the system can explain why it is safe, and sanitization/quarantine behavior is explicit and auditable.
- This repo is therefore aligned with the full prompt and current implementation status: the roadmap, docs, and phase-by-phase code are intentionally tracked together so future work can continue cleanly.