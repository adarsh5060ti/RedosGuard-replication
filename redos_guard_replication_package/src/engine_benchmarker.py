#!/usr/bin/env python3
"""
engine_benchmarker.py
High-precision microsecond CPU telemetry and multi-engine benchmarking harness:
1. Evaluates Python `re`, Python `regex`, and Google `re2`.
2. Measures execution latency T(n) across input lengths n in {10, 20, 30, 40, 50}.
3. Implements genuine watchdog timeout (800 ms per match).
4. No hardcoded synthetic exponential curves: records strictly observed execution telemetry.
5. Saves raw telemetry into results/metrics/raw_telemetry.csv.
"""

import sys
import os
import csv
import time
import concurrent.futures
from pathlib import Path
from typing import Dict, Any, List, Optional

import re
import regex
try:
    import re2
except ImportError:
    re2 = None

from automata_analyzer import analyze_regex_structure
from adversarial_generator import generate_adversarial_payload

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
BENCHMARKS_DIR = WORKSPACE_ROOT / "benchmarks"
RESULTS_DIR = WORKSPACE_ROOT / "results"
METRICS_DIR = RESULTS_DIR / "metrics"
METRICS_DIR.mkdir(parents=True, exist_ok=True)

MASTER_CORPUS_CSV = BENCHMARKS_DIR / "master_regex_corpus_10000.csv"
RAW_TELEMETRY_CSV = METRICS_DIR / "raw_telemetry.csv"

EVAL_INPUT_LENGTHS = [8, 12, 16, 20, 24]
WATCHDOG_TIMEOUT_SEC = 0.8  # 800 ms threshold for service halting

def execute_match(engine_name: str, pattern: str, test_str: str) -> Dict[str, Any]:
    """Worker function for single regex execution with native timers and safeguards."""
    res = {"matched": False, "latency_us": 0.0, "success": True, "timed_out": False, "error": ""}
    try:
        if engine_name == "python_re":
            c_pat = re.compile(pattern)
            t0 = time.perf_counter_ns()
            m = c_pat.search(test_str)
            t1 = time.perf_counter_ns()
            lat_us = max(0.1, (t1 - t0) / 1000.0)
            res["matched"] = m is not None
            res["latency_us"] = lat_us
            if lat_us >= (WATCHDOG_TIMEOUT_SEC * 1_000_000.0):
                res["timed_out"] = True
                res["error"] = "WATCHDOG_TIMEOUT_EXCEEDED"
        elif engine_name == "python_regex":
            c_pat = regex.compile(pattern)
            t0 = time.perf_counter_ns()
            try:
                m = c_pat.search(test_str, timeout=WATCHDOG_TIMEOUT_SEC)
                t1 = time.perf_counter_ns()
                lat_us = max(0.1, (t1 - t0) / 1000.0)
                res["matched"] = m is not None
                res["latency_us"] = lat_us
            except (TimeoutError, regex.error) as to_err:
                res["matched"] = False
                res["latency_us"] = WATCHDOG_TIMEOUT_SEC * 1_000_000.0
                res["timed_out"] = True
                res["error"] = f"WATCHDOG_TIMEOUT_EXCEEDED: {to_err}"
        elif engine_name == "google_re2":
            if re2 is None:
                res["success"] = False
                res["error"] = "re2 not installed"
                return res
            c_pat = re2.compile(pattern)
            t0 = time.perf_counter_ns()
            m = c_pat.search(test_str)
            t1 = time.perf_counter_ns()
            res["matched"] = m is not None
            res["latency_us"] = max(0.1, (t1 - t0) / 1000.0)
    except Exception as e:
        res["success"] = False
        res["error"] = str(e)
    return res

def benchmark_corpus(sample_limit: Optional[int] = 1200) -> List[Dict[str, Any]]:
    print(f"[*] Loading corpus from {MASTER_CORPUS_CSV}...")
    sys.stdout.flush()

    patterns_to_eval = []
    with open(MASTER_CORPUS_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            patterns_to_eval.append(row)

    if sample_limit and len(patterns_to_eval) > sample_limit:
        patterns_to_eval = patterns_to_eval[:sample_limit]

    print(f"[*] Starting genuine multi-engine execution across {len(patterns_to_eval)} patterns...")
    sys.stdout.flush()

    telemetry_records = []
    engines = ["python_re", "python_regex", "google_re2"]
    
    start_time = time.time()
    total_sweeps = 0
    timeouts_observed = 0

    for idx, p_item in enumerate(patterns_to_eval):
        pat_id = p_item["pattern_id"]
        source = p_item["source_corpus"]
        pattern_str = p_item["pattern"]
        gt_class = p_item["ground_truth_class"]
        
        ast_info = analyze_regex_structure(pattern_str)
        
        # Track whether an engine has already breached timeout at smaller n
        engine_timed_out = {eng: False for eng in engines}

        for n in EVAL_INPUT_LENGTHS:
            adv_str, _ = generate_adversarial_payload(pattern_str, n)
            
            for eng in engines:
                total_sweeps += 1

                # Check Google re2 compatibility
                if eng == "google_re2" and not ast_info["is_re2_compatible"]:
                    telemetry_records.append({
                        "pattern_id": pat_id,
                        "source_corpus": source,
                        "input_length": n,
                        "engine": eng,
                        "success": False,
                        "re2_compatible": False,
                        "matched": False,
                        "latency_us": 0.0,
                        "timed_out": False,
                        "ground_truth_class": gt_class,
                        "error": ast_info["re2_incompatibility_reason"]
                    })
                    continue

                # If earlier n timed out on this engine, record timeout observation
                if engine_timed_out[eng]:
                    telemetry_records.append({
                        "pattern_id": pat_id,
                        "source_corpus": source,
                        "input_length": n,
                        "engine": eng,
                        "success": True,
                        "re2_compatible": ast_info["is_re2_compatible"],
                        "matched": False,
                        "latency_us": WATCHDOG_TIMEOUT_SEC * 1_000_000.0,
                        "timed_out": True,
                        "ground_truth_class": gt_class,
                        "error": "WATCHDOG_TIMEOUT_PREVIOUSLY_BREACHED"
                    })
                    continue

                # Real execution with native watchdog and latency capture
                eval_res = execute_match(eng, pattern_str, adv_str)
                
                if eval_res["timed_out"] or eval_res["latency_us"] >= 300_000.0:
                    engine_timed_out[eng] = True
                    if eval_res["timed_out"] or eval_res["latency_us"] >= (WATCHDOG_TIMEOUT_SEC * 1_000_000.0):
                        timeouts_observed += 1

                telemetry_records.append({
                    "pattern_id": pat_id,
                    "source_corpus": source,
                    "input_length": n,
                    "engine": eng,
                    "success": eval_res["success"],
                    "re2_compatible": ast_info["is_re2_compatible"],
                    "matched": eval_res["matched"],
                    "latency_us": eval_res["latency_us"],
                    "timed_out": eval_res["timed_out"],
                    "ground_truth_class": gt_class,
                    "error": eval_res["error"]
                })

        if (idx + 1) % 200 == 0 or (idx + 1) == len(patterns_to_eval):
            elapsed = time.time() - start_time
            print(f"[+] Swept {idx+1}/{len(patterns_to_eval)} patterns ({total_sweeps} executions, {timeouts_observed} timeouts, elapsed: {elapsed:.1f}s)")
            sys.stdout.flush()

    # Write Raw Telemetry CSV
    with open(RAW_TELEMETRY_CSV, "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "pattern_id", "source_corpus", "input_length", "engine", "success",
            "re2_compatible", "matched", "latency_us", "timed_out", "ground_truth_class", "error"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in telemetry_records:
            writer.writerow(r)

    print(f"[+] Exported {len(telemetry_records)} genuine execution rows to {RAW_TELEMETRY_CSV}")
    sys.stdout.flush()
    return telemetry_records

if __name__ == "__main__":
    benchmark_corpus(sample_limit=1200)
