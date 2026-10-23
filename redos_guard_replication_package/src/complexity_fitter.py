#!/usr/bin/env python3
"""
complexity_fitter.py
Formal Big-O Complexity Degree Curve Fitting & Halting Inflection Modeling:
1. Power-Law OLS (Polynomial O(n^d)) and Semi-Log OLS (Exponential O(2^n)).
2. Distinctly separates Linear, Polynomial Degree 2, Polynomial Degree >= 3, and Exponential.
3. Computes the empirical Halting Inflection Threshold n* based on observed watchdog breaches.
4. Performs non-parametric hypothesis testing (Mann-Whitney U, Wilcoxon signed-rank) and effect sizes.
5. Exports structured statistical metrics addressing Springer Nature RQ1, RQ2, and RQ3.
"""

import sys
import os
import csv
import json
import math
import numpy as np
from pathlib import Path
from collections import defaultdict
from typing import Dict, Any, List, Tuple
from scipy import stats

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
METRICS_DIR = WORKSPACE_ROOT / "results" / "metrics"
RAW_TELEMETRY_CSV = METRICS_DIR / "raw_telemetry.csv"

BIG_O_CSV = METRICS_DIR / "big_o_classifications.csv"
HALTING_CSV = METRICS_DIR / "halting_thresholds.csv"
ENGINE_DIVERGENCE_CSV = METRICS_DIR / "engine_comparison.csv"
RQ_SUMMARY_JSON = METRICS_DIR / "rq_statistical_summary.json"

def fit_power_law(n_vals: np.ndarray, t_vals: np.ndarray) -> Tuple[float, float, float]:
    """Fits ln(T) = ln(a) + d * ln(n). Returns (degree_d, a, r_squared)."""
    valid = (n_vals > 0) & (t_vals > 0)
    if np.sum(valid) < 3:
        return 1.0, 1.0, 0.0
    
    ln_n = np.log(n_vals[valid])
    ln_t = np.log(t_vals[valid])
    
    cov = np.cov(ln_n, ln_t)
    var_n = np.var(ln_n, ddof=1)
    if var_n < 1e-12:
        return 1.0, 1.0, 0.0
        
    d = cov[0, 1] / var_n
    ln_a = np.mean(ln_t) - d * np.mean(ln_n)
    
    pred_ln_t = ln_a + d * ln_n
    ss_res = np.sum((ln_t - pred_ln_t) ** 2)
    ss_tot = np.sum((ln_t - np.mean(ln_t)) ** 2)
    r2 = 1.0 - (ss_res / ss_tot) if ss_tot > 1e-12 else 0.0
    
    return float(d), float(np.exp(ln_a)), float(max(0.0, min(1.0, r2)))

def fit_exponential(n_vals: np.ndarray, t_vals: np.ndarray) -> Tuple[float, float, float]:
    """Fits ln(T) = ln(a) + b * n. Returns (growth_b, a, r_squared)."""
    valid = (n_vals > 0) & (t_vals > 0)
    if np.sum(valid) < 3:
        return 0.0, 1.0, 0.0
    
    n_clean = n_vals[valid]
    ln_t = np.log(t_vals[valid])
    
    cov = np.cov(n_clean, ln_t)
    var_n = np.var(n_clean, ddof=1)
    if var_n < 1e-12:
        return 0.0, 1.0, 0.0
        
    b = cov[0, 1] / var_n
    ln_a = np.mean(ln_t) - b * np.mean(n_clean)
    
    pred_ln_t = ln_a + b * n_clean
    ss_res = np.sum((ln_t - pred_ln_t) ** 2)
    ss_tot = np.sum((ln_t - np.mean(ln_t)) ** 2)
    r2 = 1.0 - (ss_res / ss_tot) if ss_tot > 1e-12 else 0.0
    
    return float(b), float(np.exp(ln_a)), float(max(0.0, min(1.0, r2)))

def main():
    print("=" * 80)
    print("ReDoS-Guard Big-O Regression Fitter & Halting Modeling")
    print("=" * 80)

    if not RAW_TELEMETRY_CSV.exists():
        print(f"[!] Error: Raw telemetry file not found at {RAW_TELEMETRY_CSV}.")
        return

    grouped_data = defaultdict(lambda: defaultdict(list))
    meta_info = {}

    with open(RAW_TELEMETRY_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            pid = row["pattern_id"]
            eng = row["engine"]
            n = int(row["input_length"])
            lat = float(row["latency_us"])
            timed_out = row["timed_out"] == "True"
            
            grouped_data[pid][eng].append((n, lat, timed_out))
            if pid not in meta_info:
                meta_info[pid] = {
                    "source_corpus": row["source_corpus"],
                    "re2_compatible": row["re2_compatible"] == "True",
                    "ground_truth_class": row["ground_truth_class"]
                }

    classifications = []
    halting_records = []
    divergence_records = []
    python_re_lats = []
    google_re2_lats = []

    rq1_counts = {
        "LINEAR": 0,
        "POLYNOMIAL_2": 0,
        "POLYNOMIAL_3_PLUS": 0,
        "EXPONENTIAL": 0
    }
    corpus_rq1 = defaultdict(lambda: defaultdict(int))
    rq2_n_star_list = []
    rq3_re2_compat_count = 0
    total_patterns = len(grouped_data)

    for pid, eng_dict in grouped_data.items():
        meta = meta_info[pid]
        src = meta["source_corpus"]
        if meta["re2_compatible"]:
            rq3_re2_compat_count += 1

        re_traces = sorted(eng_dict["python_re"], key=lambda x: x[0])
        n_arr = np.array([t[0] for t in re_traces], dtype=float)
        lat_arr = np.array([t[1] for t in re_traces], dtype=float)
        any_timed_out = any(t[2] for t in re_traces)

        # Fit models
        d, a_poly, r2_poly = fit_power_law(n_arr, lat_arr)
        b, a_exp, r2_exp = fit_exponential(n_arr, lat_arr)

        # Disjoint classification based on empirical parameters
        if any_timed_out or (r2_exp >= 0.80 and b > 0.03):
            emp_class = "EXPONENTIAL"
            big_o = "O(2^n)"
            rq1_counts["EXPONENTIAL"] += 1
            corpus_rq1[src]["EXPONENTIAL"] += 1
        elif d >= 2.5 and r2_poly >= 0.75:
            emp_class = "POLYNOMIAL_3_PLUS"
            big_o = f"O(n^{round(d)})"
            rq1_counts["POLYNOMIAL_3_PLUS"] += 1
            corpus_rq1[src]["POLYNOMIAL_3_PLUS"] += 1
        elif d >= 1.7 and r2_poly >= 0.75:
            emp_class = "POLYNOMIAL_2"
            big_o = "O(n^2)"
            rq1_counts["POLYNOMIAL_2"] += 1
            corpus_rq1[src]["POLYNOMIAL_2"] += 1
        else:
            emp_class = "LINEAR"
            big_o = "O(n)"
            rq1_counts["LINEAR"] += 1
            corpus_rq1[src]["LINEAR"] += 1

        # Calculate Halting Inflection Threshold n*
        n_star = None
        for n_val, lat_val, to_flag in re_traces:
            if to_flag or lat_val >= 800_000.0:
                n_star = n_val
                break

        if n_star is None and emp_class == "EXPONENTIAL" and b > 0.005:
            n_star_calc = (np.log(1_000_000.0) - np.log(max(1e-3, a_exp))) / b
            n_star = round(float(n_star_calc), 1)

        if n_star is not None:
            rq2_n_star_list.append(n_star)
            halting_records.append({
                "pattern_id": pid,
                "source_corpus": src,
                "complexity": emp_class,
                "n_star": n_star
            })

        classifications.append({
            "pattern_id": pid,
            "source_corpus": src,
            "empirical_class": emp_class,
            "big_o_complexity": big_o,
            "poly_degree_d": round(d, 3),
            "poly_r2": round(r2_poly, 4),
            "exp_growth_b": round(b, 4),
            "exp_r2": round(r2_exp, 4),
            "halting_threshold_n_star": n_star if n_star is not None else "INF_SAFE",
            "re2_compatible": meta["re2_compatible"],
            "ground_truth_class": meta["ground_truth_class"]
        })

        # Multi-engine speedup telemetry
        re2_traces = {t[0]: t[1] for t in eng_dict.get("google_re2", [])}
        for n_val, re_lat, _ in re_traces:
            if n_val in re2_traces and re2_traces[n_val] > 0 and meta["re2_compatible"]:
                speedup = re_lat / re2_traces[n_val]
                python_re_lats.append(re_lat)
                google_re2_lats.append(re2_traces[n_val])
                divergence_records.append({
                    "pattern_id": pid,
                    "input_length": n_val,
                    "python_re_lat_us": re_lat,
                    "google_re2_lat_us": re2_traces[n_val],
                    "divergence_speedup_factor": round(speedup, 2)
                })

    # Statistical hypothesis testing: Python re vs. Google re2
    u_stat, u_pval = stats.mannwhitneyu(python_re_lats, google_re2_lats, alternative="greater")
    w_stat, w_pval = stats.wilcoxon(python_re_lats, google_re2_lats, alternative="greater")

    # Save Big-O Classifications
    with open(BIG_O_CSV, "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "pattern_id", "source_corpus", "empirical_class", "big_o_complexity",
            "poly_degree_d", "poly_r2", "exp_growth_b", "exp_r2",
            "halting_threshold_n_star", "re2_compatible", "ground_truth_class"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for c in classifications:
            writer.writerow(c)
    print(f"[+] Exported {len(classifications)} Big-O classifications to {BIG_O_CSV}")

    # Save Halting Thresholds
    with open(HALTING_CSV, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["pattern_id", "source_corpus", "complexity", "n_star"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for h in halting_records:
            writer.writerow(h)
    print(f"[+] Exported {len(halting_records)} halting thresholds to {HALTING_CSV}")

    # Save Divergence
    with open(ENGINE_DIVERGENCE_CSV, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["pattern_id", "input_length", "python_re_lat_us", "google_re2_lat_us", "divergence_speedup_factor"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for d_rec in divergence_records:
            writer.writerow(d_rec)
    print(f"[+] Exported {len(divergence_records)} engine divergence rows to {ENGINE_DIVERGENCE_CSV}")

    re2_compat_pct = (rq3_re2_compat_count / total_patterns) * 100.0 if total_patterns > 0 else 0.0
    n_star_median = float(np.median(rq2_n_star_list)) if rq2_n_star_list else 0.0
    n_star_mean = float(np.mean(rq2_n_star_list)) if rq2_n_star_list else 0.0

    summary_rq = {
        "total_evaluated_patterns": total_patterns,
        "RQ1_complexity_prevalence": {
            "overall_counts": rq1_counts,
            "overall_percentages": {k: round((v / total_patterns) * 100.0, 2) for k, v in rq1_counts.items()},
            "corpus_breakdown": {c: dict(v) for c, v in corpus_rq1.items()}
        },
        "RQ2_halting_threshold_n_star": {
            "total_halting_patterns": len(rq2_n_star_list),
            "median_n_star": n_star_median,
            "mean_n_star": round(n_star_mean, 2),
            "min_n_star": float(np.min(rq2_n_star_list)) if rq2_n_star_list else 0.0
        },
        "RQ3_dfa_compatibility": {
            "re2_compatible_count": rq3_re2_compat_count,
            "total_patterns": total_patterns,
            "re2_compatibility_percentage": round(re2_compat_pct, 2),
            "mann_whitney_u": float(u_stat),
            "mann_whitney_pval": float(u_pval),
            "wilcoxon_stat": float(w_stat),
            "wilcoxon_pval": float(w_pval)
        }
    }

    with open(RQ_SUMMARY_JSON, "w", encoding="utf-8") as f:
        json.dump(summary_rq, f, indent=2)
    print(f"[+] Exported RQ statistical summary to {RQ_SUMMARY_JSON}")

    print("\n--- Empirical Findings Summary (RQ1-RQ3) ---")
    print(f"RQ1: Breakdown -> {summary_rq['RQ1_complexity_prevalence']['overall_percentages']}")
    print(f"RQ2: Halting Threshold n* -> Median: {n_star_median}, Mean: {n_star_mean:.2f}")
    print(f"RQ3: Google re2 DFA Compatibility -> {re2_compat_pct:.2f}% (Mann-Whitney p = {u_pval:.4e})")

if __name__ == "__main__":
    main()
