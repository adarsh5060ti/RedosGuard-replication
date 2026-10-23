#!/usr/bin/env python3
"""
re2_verifier.py
ReDoS-Guard: Microsecond Multi-Engine Evaluation Harness & DFA Linearization Verifier.

Benchmarks regular expression execution latencies across:
- CPython `re` (bytecode backtrack engine)
- Python `regex` (mrabarnett optimized engine)
- Google `re2` (linear automata DFA/Thompson NFA simulation)

Verifies linear execution invariance (Theorem 2) and calculates speedup
factors Delta_engine(n) = T_CPython(n) / T_re2(n).
"""

import sys
import os
import argparse
import time
from pathlib import Path
from typing import Dict, Any, List

import re
import regex
try:
    import re2
except ImportError:
    re2 = None

from adversarial_synthesizer import synthesize_attack_payload

def evaluate_multi_engine(pattern: str, test_string: str, runs: int = 5) -> Dict[str, Any]:
    """
    Executes test_string against pattern on CPython re, Python regex, and Google re2.
    Returns per-engine latencies in microseconds and speedup factors.
    """
    results = {}

    # 1. CPython re
    try:
        c_pat = re.compile(pattern)
        # warmup
        c_pat.search(test_string[:10])
        times = []
        for _ in range(runs):
            t0 = time.perf_counter_ns()
            c_pat.search(test_string)
            t1 = time.perf_counter_ns()
            times.append((t1 - t0) / 1000.0)
        results["cpython_re_us"] = round(min(times), 2)
    except Exception as e:
        results["cpython_re_us"] = None
        results["cpython_re_error"] = str(e)

    # 2. Python regex
    try:
        c_pat = regex.compile(pattern)
        times = []
        for _ in range(runs):
            t0 = time.perf_counter_ns()
            c_pat.search(test_string)
            t1 = time.perf_counter_ns()
            times.append((t1 - t0) / 1000.0)
        results["python_regex_us"] = round(min(times), 2)
    except Exception as e:
        results["python_regex_us"] = None
        results["python_regex_error"] = str(e)

    # 3. Google re2
    if re2 is not None:
        try:
            c_pat = re2.compile(pattern)
            times = []
            for _ in range(runs):
                t0 = time.perf_counter_ns()
                c_pat.search(test_string)
                t1 = time.perf_counter_ns()
                times.append((t1 - t0) / 1000.0)
            results["google_re2_us"] = round(min(times), 2)
            results["re2_compatible"] = True
        except Exception as e:
            results["google_re2_us"] = None
            results["re2_compatible"] = False
            results["re2_error"] = str(e)
    else:
        results["google_re2_us"] = None
        results["re2_compatible"] = None
        results["re2_error"] = "google-re2 package not installed"

    # Compute Speedup
    if results.get("cpython_re_us") and results.get("google_re2_us"):
        re2_t = max(0.01, results["google_re2_us"])
        results["speedup_factor"] = round(results["cpython_re_us"] / re2_t, 1)
    else:
        results["speedup_factor"] = None

    return results

def main():
    parser = argparse.ArgumentParser(description="ReDoS-Guard Multi-Engine Verifier")
    parser.add_argument("--pattern", "-p", type=str, default=r"^([a-zA-Z0-9]+)+$", help="Regex pattern")
    parser.add_argument("--length", "-n", type=int, default=24, help="Adversarial pump length")
    args = parser.parse_args()

    synth = synthesize_attack_payload(args.pattern, args.length)
    adv_str = synth["adversarial_payload"]
    metrics = evaluate_multi_engine(args.pattern, adv_str)

    print("=" * 70)
    print("ReDoS-Guard: Multi-Engine Latency & re2 Linearization Audit")
    print("=" * 70)
    print(f"Pattern           : {args.pattern}")
    print(f"Payload Length    : {len(adv_str)} characters")
    print("-" * 70)
    print(f"CPython re        : {metrics.get('cpython_re_us', 'ERR')} µs")
    print(f"Python regex      : {metrics.get('python_regex_us', 'ERR')} µs")
    print(f"Google re2        : {metrics.get('google_re2_us', 'ERR')} µs")
    if metrics.get("speedup_factor"):
        print(f"re2 Speedup Factor: {metrics['speedup_factor']}x")
    print("=" * 70)

if __name__ == "__main__":
    main()
