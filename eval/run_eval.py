from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from eval.generate_corpus import BENIGN_SAMPLES, generate_corpus
from eval.report import generate_markdown_report
from pifw.config import FirewallConfig
from pifw.extractors.router import extract_payload
from pifw.firewall import Firewall
from pifw.models import Action, AttackType


def run_eval(report_path: str | Path = "eval/results/report.md") -> dict[str, Any]:
    print("=> Generating evaluation corpus...")
    corpus = generate_corpus("eval/corpus")
    attack_files = corpus["attack_files"]

    firewall = Firewall()

    per_attack_counts: dict[str, list[bool]] = {at.value: [] for at in AttackType}
    per_format_counts: dict[str, list[bool]] = {}
    all_latencies: list[float] = []

    print(f"=> Evaluating {len(attack_files)} attack samples...")
    for sample_idx, file_path_str in enumerate(attack_files, start=1):
        file_path = Path(file_path_str)
        ext = file_path.suffix.lstrip(".") or "text"
        filename = file_path.name

        # Find attack type from filename
        attack_type_str = "unknown"
        for at in AttackType:
            if f"_{at.value}_" in filename:
                attack_type_str = at.value
                break

        data = file_path.read_bytes()
        chunks = extract_payload(data, filename=filename)
        combined_text = "\n".join(c.text for c in chunks)

        start = time.perf_counter()
        verdict = firewall.scan(combined_text, session_id=f"attack_sample_{sample_idx}")
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        all_latencies.append(elapsed_ms)

        detected = verdict.action in (Action.BLOCK, Action.QUARANTINE, Action.SANITIZE)

        if attack_type_str in per_attack_counts:
            per_attack_counts[attack_type_str].append(detected)

        if ext not in per_format_counts:
            per_format_counts[ext] = []
        per_format_counts[ext].append(detected)

    # Calculate recall per attack type
    per_attack_recall = {}
    total_detected = 0
    total_samples = 0
    for at_str, results in per_attack_counts.items():
        if results:
            rec = sum(results) / len(results)
            per_attack_recall[at_str] = rec
            total_detected += sum(results)
            total_samples += len(results)

    overall_recall = total_detected / max(total_samples, 1)

    # Calculate recall per format
    per_format_recall = {}
    for fmt, results in per_format_counts.items():
        if results:
            per_format_recall[fmt] = sum(results) / len(results)

    # Calculate false positive rate on benign samples
    print(f"=> Evaluating {len(BENIGN_SAMPLES)} benign samples...")
    fp_count = 0
    for b_idx, b_text in enumerate(BENIGN_SAMPLES, start=1):
        v = firewall.scan(b_text, session_id=f"benign_sample_{b_idx}")
        if v.action in (Action.BLOCK, Action.QUARANTINE, Action.SANITIZE):
            fp_count += 1

    fpr = fp_count / max(len(BENIGN_SAMPLES), 1)

    # Compute latency percentiles
    all_latencies.sort()
    p50 = all_latencies[len(all_latencies) // 2] if all_latencies else 0.0
    p95 = all_latencies[int(len(all_latencies) * 0.95)] if all_latencies else 0.0

    # Layer Ablation Study
    print("=> Running layer ablation study...")
    ablation = {}
    for config_name, layers in [
        ("L1_rules_only", ["L1"]),
        ("L1+structural", ["L1", "structural"]),
        ("L1+structural+session", ["L1", "structural", "session"]),
        ("Full_pipeline", ["L1", "L2", "L3", "structural", "session", "egress", "canary", "tool_guard"]),
    ]:
        fw_ablation = Firewall(config=FirewallConfig(enabled_layers=layers))
        det = 0
        for sample_idx, file_path_str in enumerate(attack_files, start=1):
            text = Path(file_path_str).read_text(encoding="utf-8", errors="ignore")
            if fw_ablation.scan(text, session_id=f"ablation_{config_name}_{sample_idx}").action in (Action.BLOCK, Action.QUARANTINE, Action.SANITIZE):
                det += 1
        ablation[config_name] = det / max(len(attack_files), 1)

    metrics = {
        "overall_recall": overall_recall,
        "per_attack_recall": per_attack_recall,
        "per_format_recall": per_format_recall,
        "false_positive_rate": fpr,
        "latency_p50_ms": p50,
        "latency_p95_ms": p95,
        "ablation": ablation,
    }

    generate_markdown_report(metrics, report_path)
    print(f"=> Evaluation complete! Report saved to {report_path}")
    return metrics


if __name__ == "__main__":
    run_eval()
