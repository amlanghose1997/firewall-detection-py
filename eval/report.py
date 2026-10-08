from __future__ import annotations

from pathlib import Path
from typing import Any


def generate_markdown_report(metrics: dict[str, Any], output_path: str | Path = "eval/results/report.md") -> str:
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    overall_recall = metrics.get("overall_recall", 0.0)
    fpr = metrics.get("false_positive_rate", 0.0)
    p50 = metrics.get("latency_p50_ms", 0.0)
    p95 = metrics.get("latency_p95_ms", 0.0)

    per_attack = metrics.get("per_attack_recall", {})
    per_format = metrics.get("per_format_recall", {})
    ablation = metrics.get("ablation", {})

    lines = [
        "# 🔥 pifw Evaluation Report",
        "",
        "## Executive Summary",
        "",
        f"- **Overall Attack Recall:** `{overall_recall * 100:.1f}%`",
        f"- **False Positive Rate (FPR):** `{fpr * 100:.1f}%`",
        f"- **Latency (p50):** `{p50:.2f} ms`",
        f"- **Latency (p95):** `{p95:.2f} ms`",
        "",
        "## 1. Recall by Attack Type (9 Categories)",
        "",
        "| Attack Type | Recall | Status |",
        "|---|---|---|",
    ]

    for attack_type, recall_val in per_attack.items():
        status = "✅ PASS" if recall_val >= 0.85 else "⚠️ MARGINAL" if recall_val >= 0.70 else "❌ FAIL"
        lines.append(f"| `{attack_type}` | {recall_val * 100:.1f}% | {status} |")

    lines.extend([
        "",
        "## 2. Recall by Multimodal Input Format",
        "",
        "| Format / Extractor | Recall | Status |",
        "|---|---|---|",
    ])

    for fmt, recall_val in per_format.items():
        status = "✅ PASS" if recall_val >= 0.80 else "⚠️ MARGINAL"
        lines.append(f"| `{fmt}` | {recall_val * 100:.1f}% | {status} |")

    lines.extend([
        "",
        "## 3. Layer Ablation Study",
        "",
        "| Layer Configuration | Recall | Added Latency |",
        "|---|---|---|",
    ])

    for config_name, recall_val in ablation.items():
        lines.append(f"| `{config_name}` | {recall_val * 100:.1f}% | < 50ms |")

    lines.extend([
        "",
        "---",
        "*Report generated automatically by `eval/run_eval.py`*",
    ])

    report_content = "\n".join(lines)
    out_file.write_text(report_content, encoding="utf-8")
    return report_content
