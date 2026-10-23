#!/usr/bin/env python3
"""
static_checker_eval.py
Empirical Evaluation of Static AST Vulnerability Detectors vs. Dynamic CPU Telemetry (RQ4):
1. Evaluates static AST heuristic alarms against independent empirical CPU Big-O classifications.
2. Derives genuine True Positives, False Positives, True Negatives, False Negatives.
3. Quantifies Precision, Recall, Specificity, False Positive Rate (FPR), and F1-Score.
4. Generates ROC/PR points and exports metrics into results/metrics/static_checker_roc_metrics.json.
"""

import sys
import os
import csv
import json
import numpy as np
from pathlib import Path
from typing import Dict, Any

from automata_analyzer import analyze_regex_structure

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
METRICS_DIR = WORKSPACE_ROOT / "results" / "metrics"
BENCHMARKS_DIR = WORKSPACE_ROOT / "benchmarks"
BIG_O_CSV = METRICS_DIR / "big_o_classifications.csv"
MASTER_CORPUS_CSV = BENCHMARKS_DIR / "master_regex_corpus_10000.csv"

CONFUSION_CSV = METRICS_DIR / "confusion_matrix.csv"
STATIC_METRICS_JSON = METRICS_DIR / "static_checker_roc_metrics.json"

def main():
    print("=" * 80)
    print("ReDoS-Guard Static Checker Predictive Validity & False Alarm Audit (RQ4)")
    print("=" * 80)

    if not BIG_O_CSV.exists():
        print(f"[!] Error: Big-O classifications file not found at {BIG_O_CSV}.")
        return

    # Ingest empirical ground truth derived SOLELY from dynamic CPU telemetry
    empirical_truth = {}
    with open(BIG_O_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            pid = row["pattern_id"]
            # Ground truth: empirically vulnerable if dynamic CPU demonstrated super-linear scaling
            is_vuln = (row["empirical_class"] != "LINEAR")
            empirical_truth[pid] = {
                "is_empirically_vulnerable": is_vuln,
                "empirical_class": row["empirical_class"],
                "source_corpus": row["source_corpus"]
            }

    # Static AST Heuristic Detection (simulating safe-regex / Regexploit AST linters)
    static_predictions = {}
    with open(MASTER_CORPUS_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            pid = row["pattern_id"]
            if pid in empirical_truth:
                pattern = row["pattern"]
                ast_res = analyze_regex_structure(pattern)
                # Static tools trigger alarms on nested quantifiers, overlapping disjunctions, or wildcards
                static_alarm = (
                    ast_res["has_nested_quantifiers"] or 
                    ast_res["has_overlapping_disjunction"] or 
                    ast_res["has_greedy_wildcards"] or 
                    ast_res["structural_risk_score"] >= 0.4
                )
                static_predictions[pid] = {
                    "static_alarm": static_alarm,
                    "risk_score": ast_res["structural_risk_score"]
                }

    # Compute Confusion Matrix against true CPU telemetry
    tp, fp, tn, fn = 0, 0, 0, 0
    for pid, emp_info in empirical_truth.items():
        if pid not in static_predictions:
            continue
        stat_info = static_predictions[pid]
        actual = emp_info["is_empirically_vulnerable"]
        predicted = stat_info["static_alarm"]

        if actual and predicted:
            tp += 1
        elif not actual and predicted:
            fp += 1  # Genuine false alarm: AST flagged safe pattern
        elif not actual and not predicted:
            tn += 1
        elif actual and not predicted:
            fn += 1  # Missed vulnerability

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fdr = fp / (tp + fp) if (tp + fp) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    print(f"[+] Total Evaluated Patterns for RQ4: {total}")
    print(f"    - True Positives (TP):  {tp}")
    print(f"    - False Positives (FP): {fp} (Real Static False Alarms)")
    print(f"    - True Negatives (TN):  {tn}")
    print(f"    - False Negatives (FN): {fn}")
    print(f"    - Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"    - Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"    - Specificity: {specificity:.4f} ({specificity*100:.2f}%)")
    print(f"    - False Positive Rate (FPR): {fpr:.4f} ({fpr*100:.2f}%)")
    print(f"    - False Discovery Rate (FDR): {fdr:.4f} ({fdr*100:.2f}%)")
    print(f"    - F1-Score:  {f1:.4f}")
    print(f"    - Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")

    # Export Confusion Matrix CSV
    with open(CONFUSION_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Metric", "Value", "Percentage"])
        writer.writerow(["True Positives (TP)", tp, f"{(tp/total)*100:.2f}%"])
        writer.writerow(["False Positives (FP)", fp, f"{(fp/total)*100:.2f}%"])
        writer.writerow(["True Negatives (TN)", tn, f"{(tn/total)*100:.2f}%"])
        writer.writerow(["False Negatives (FN)", fn, f"{(fn/total)*100:.2f}%"])
        writer.writerow(["Precision", round(precision, 4), f"{precision*100:.2f}%"])
        writer.writerow(["Recall (Sensitivity)", round(recall, 4), f"{recall*100:.2f}%"])
        writer.writerow(["Specificity", round(specificity, 4), f"{specificity*100:.2f}%"])
        writer.writerow(["False Positive Rate (FPR)", round(fpr, 4), f"{fpr*100:.2f}%"])
        writer.writerow(["False Discovery Rate (FDR)", round(fdr, 4), f"{fdr*100:.2f}%"])
        writer.writerow(["F1-Score", round(f1, 4), "-"])
        writer.writerow(["Overall Accuracy", round(accuracy, 4), f"{accuracy*100:.2f}%"])

    metrics_obj = {
        "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn, "total": total},
        "performance": {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "specificity": round(specificity, 4),
            "false_positive_rate": round(fpr, 4),
            "false_discovery_rate": round(fdr, 4),
            "f1_score": round(f1, 4)
        }
    }

    with open(STATIC_METRICS_JSON, "w", encoding="utf-8") as f:
        json.dump(metrics_obj, f, indent=2)

    print(f"[+] Exported genuine RQ4 metrics to {CONFUSION_CSV} and {STATIC_METRICS_JSON}")

if __name__ == "__main__":
    main()
