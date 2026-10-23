#!/usr/bin/env python3
"""
adversarial_synthesizer.py
ReDoS-Guard: Automated AST Cycle Extraction & Adversarial Payload Generation.

Formal operational semantics implementation:
Synthesizes parameterized attack vectors w(n) = u_prefix * (w_p)^n * w_suffix
via AST parsing and Tarjan strongly connected components (SCC) cycle extraction
to rigorously trigger algorithmic complexity breakdown in backtracking NFAs.
"""

import sys
import os
import argparse
from pathlib import Path
from typing import Tuple, Dict, Any, List

from automata_analyzer import analyze_regex_structure
from adversarial_generator import generate_adversarial_payload, extract_pump_character

def synthesize_attack_payload(pattern: str, pump_length: int = 30) -> Dict[str, Any]:
    """
    Synthesizes a three-part attack vector w(n) = u_prefix * (w_p)^n * w_suffix
    and baseline benign control string for a given regular expression.
    """
    struct_info = analyze_regex_structure(pattern)
    adv_payload, benign_payload = generate_adversarial_payload(pattern, pump_length)
    pump_char = extract_pump_character(pattern)
    
    return {
        "pattern": pattern,
        "pump_length": pump_length,
        "pump_token": pump_char,
        "adversarial_payload": adv_payload,
        "benign_payload": benign_payload,
        "has_nested_quantifiers": struct_info.get("has_nested_quantifiers", False),
        "has_overlapping_alternations": struct_info.get("has_overlapping_alternations", False),
        "is_re2_compatible": struct_info.get("re2_compatible", True),
        "star_height": struct_info.get("star_height", 0)
    }

def main():
    parser = argparse.ArgumentParser(description="ReDoS-Guard Adversarial Payload Synthesizer")
    parser.add_argument("--pattern", "-p", type=str, default=r"^(a+)+$", help="Regex pattern to analyze")
    parser.add_argument("--length", "-n", type=int, default=30, help="Pump repetition length n")
    args = parser.parse_args()

    res = synthesize_attack_payload(args.pattern, args.length)
    print("=" * 70)
    print("ReDoS-Guard: Adversarial Payload Synthesis")
    print("=" * 70)
    print(f"Target Pattern    : {res['pattern']}")
    print(f"Pump Token (w_p)  : {repr(res['pump_token'])}")
    print(f"Pump Iterations   : n = {res['pump_length']}")
    print(f"Nested Quantifiers: {res['has_nested_quantifiers']}")
    print(f"re2 Compatible    : {res['is_re2_compatible']}")
    print("-" * 70)
    print(f"Adversarial String: {res['adversarial_payload'][:80]}...")
    print(f"Benign String     : {res['benign_payload'][:80]}...")
    print("=" * 70)

if __name__ == "__main__":
    main()
