#!/usr/bin/env python3
"""
automata_analyzer.py
Performs static automata AST analysis and structural complexity classification:
1. Detects nested quantifiers (star-of-star, plus-of-plus, nested groups).
2. Detects overlapping disjunction cycles and greedy wildcard sequences.
3. Formally evaluates DFA linearizability via Google re2 compilation compatibility.
4. Identifies lookaround assertions, backreferences, and features unsupported by DFAs.
"""

import sys
import re
from typing import Dict, Any, Tuple

try:
    import re2
except ImportError:
    re2 = None

# Structural vulnerability patterns in regex AST
NESTED_QUANT_PATTERN = re.compile(r"(\([^\(\)]*[\+\*]\)[*+])|(\[[^\]]*\]\+[\+\*])|(\([^\(\)]*\{[0-9,]+\}\)[*+])")
DISJUNCTION_OVERLAP_PATTERN = re.compile(r"\(([^|()]+)\|([^|()]+)\)[\+\*]")
GREEDY_WILDCARD_PATTERN = re.compile(r"(\.\*|\.\+)[^$]*(\.\*|\.\+)")
LOOKAROUND_PATTERN = re.compile(r"\(\?[=!<]")
BACKREF_PATTERN = re.compile(r"\\([1-9]|k<[^>]+>)")
ATOMIC_POSSESSIVE_PATTERN = re.compile(r"\(\?>|\*\+|\+\+")

def analyze_regex_structure(pattern_str: str) -> Dict[str, Any]:
    """Analyzes structural automata properties and DFA compatibility of a regex."""
    result = {
        "pattern": pattern_str,
        "length": len(pattern_str),
        "has_nested_quantifiers": False,
        "has_overlapping_disjunction": False,
        "has_greedy_wildcards": False,
        "has_lookaround": False,
        "has_backreference": False,
        "has_atomic_or_possessive": False,
        "is_re2_compatible": False,
        "re2_incompatibility_reason": "",
        "predicted_complexity_class": "LINEAR",
        "structural_risk_score": 0.0
    }

    # 1. Lookaround and Backreferences
    if LOOKAROUND_PATTERN.search(pattern_str):
        result["has_lookaround"] = True
    if BACKREF_PATTERN.search(pattern_str):
        result["has_backreference"] = True
    if ATOMIC_POSSESSIVE_PATTERN.search(pattern_str):
        result["has_atomic_or_possessive"] = True

    # 2. Nested Quantifiers
    if NESTED_QUANT_PATTERN.search(pattern_str):
        result["has_nested_quantifiers"] = True
        result["structural_risk_score"] += 0.8

    # 3. Disjunction overlap
    m_disj = DISJUNCTION_OVERLAP_PATTERN.search(pattern_str)
    if m_disj:
        b1, b2 = m_disj.group(1), m_disj.group(2)
        # Check if branches share common prefix or characters
        if b1 == b2 or b1 in b2 or b2 in b1:
            result["has_overlapping_disjunction"] = True
            result["structural_risk_score"] += 0.7

    # 4. Greedy wildcards
    if GREEDY_WILDCARD_PATTERN.search(pattern_str):
        result["has_greedy_wildcards"] = True
        result["structural_risk_score"] += 0.4

    # 5. Determine predicted complexity class based on AST features
    if result["has_nested_quantifiers"] or result["has_overlapping_disjunction"]:
        result["predicted_complexity_class"] = "EXPONENTIAL"
    elif result["has_greedy_wildcards"]:
        result["predicted_complexity_class"] = "POLYNOMIAL"
    else:
        result["predicted_complexity_class"] = "LINEAR"

    # 6. Google re2 Compilation Compatibility Audit (RQ3)
    if re2 is not None:
        try:
            re2.compile(pattern_str)
            result["is_re2_compatible"] = True
        except Exception as e:
            result["is_re2_compatible"] = False
            result["re2_incompatibility_reason"] = str(e)
    else:
        # Fallback heuristic if re2 binary is missing
        if result["has_lookaround"]:
            result["is_re2_compatible"] = False
            result["re2_incompatibility_reason"] = "lookaround assertions not supported by DFA"
        elif result["has_backreference"]:
            result["is_re2_compatible"] = False
            result["re2_incompatibility_reason"] = "backreferences not supported by DFA"
        else:
            result["is_re2_compatible"] = True

    return result

if __name__ == "__main__":
    test_cases = [
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        r"^(a+)+$",
        r"^(a|a)+$",
        r"^.*a.*b.*c$",
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$"
    ]
    for tc in test_cases:
        res = analyze_regex_structure(tc)
        print(f"Pattern: {tc}")
        print(f"  Predicted: {res['predicted_complexity_class']}, re2 Compatible: {res['is_re2_compatible']} ({res['re2_incompatibility_reason']})")
