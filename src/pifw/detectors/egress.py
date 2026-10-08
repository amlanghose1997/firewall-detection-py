from __future__ import annotations

import re

SECRETS_RE = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|"
    r"eyJ[a-zA-Z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)

MARKDOWN_BEACON_RE = re.compile(
    r"!\[[^\]]*\]\((https?://[^\s)]+?\?[^\s)]*?=[A-Za-z0-9+/=]{12,})\)"
)

ENCODED_ATTACHMENT_RE = re.compile(
    r"(?:data:text/html|data:application/javascript);base64,[A-Za-z0-9+/=]{16,}"
)

SUSPICIOUS_LOCAL_RE = re.compile(
    r"(?:169\.254\.169\.254|127\.0\.0\.1|localhost|\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b)"
)

QUERY_STEG_RE = re.compile(
    r"https?://[^\s)]+?\?[a-zA-Z0-9_-]+=(?:[A-Za-z0-9+/]{20,}={0,2}|[0-9a-fA-F]{32,})"
)

KEY_LIKE_ASSIGN_RE = re.compile(
    r"(?:api[_ -]?key|token|secret|password|private_key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?",
    re.IGNORECASE,
)


def scan_egress(text: str) -> list[str]:
    findings: list[str] = []
    if SECRETS_RE.search(text):
        findings.append("secret-pattern")
    if MARKDOWN_BEACON_RE.search(text):
        findings.append("markdown-image-url")
    if ENCODED_ATTACHMENT_RE.search(text):
        findings.append("encoded-attachment")
    if SUSPICIOUS_LOCAL_RE.search(text):
        findings.append("suspicious-local-url")
    if QUERY_STEG_RE.search(text):
        findings.append("query-steg")
    if KEY_LIKE_ASSIGN_RE.search(text):
        findings.append("key-like-assign")
    return findings
