#!/usr/bin/env python3
"""
adversarial_generator.py
Synthesizes adversarial pump strings w^k + s tailored to individual regex ASTs to trigger
worst-case backtracking exploration in non-deterministic finite automata (NFAs).
Also generates benign matching strings to serve as empirical baseline controls.
"""

import re
from typing import Tuple, Dict, Any

def extract_pump_character(pattern_str: str) -> str:
    """Extracts the most likely pump token from a regex pattern."""
    # Look for characters inside repeating groups
    m = re.search(r"\[([a-zA-Z0-9_\-]+)\]", pattern_str)
    if m:
        chars = m.group(1)
        if "0-9" in chars or r"\d" in chars:
            return "1"
        if "a-z" in chars or "a-zA-Z" in chars:
            return "a"
        return chars[0]
    
    m_lit = re.search(r"\(([a-zA-Z0-9]+)[\+\*]\)", pattern_str)
    if m_lit:
        return m_lit.group(1)[0]
    
    m_single = re.search(r"([a-zA-Z0-9])[\+\*]", pattern_str)
    if m_single:
        return m_single.group(1)
        
    return "a"

def generate_adversarial_payload(pattern_str: str, length: int) -> Tuple[str, str]:
    """
    Generates:
    1. adversarial_string: Designed to trigger maximum backtracking before failing.
    2. benign_string: Designed to match or quickly exit linearly.
    """
    pump_char = extract_pump_character(pattern_str)
    
    # Adversarial payload: pump repeated length times + mismatch trigger
    # Mismatch character chosen to avoid matching pump_char
    mismatch_char = "!" if pump_char != "!" else "?"
    if pump_char in "0123456789":
        mismatch_char = "X"
    elif pump_char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":
        mismatch_char = "!"
    
    # If the pattern is an email pattern
    if "@" in pattern_str:
        user_part = "user" + (pump_char * max(1, length - 15))
        adversarial_string = user_part + "@domain" + mismatch_char
        benign_string = "user" + (pump_char * max(1, length - 15)) + "@domain.com"
    # If URL
    elif "http" in pattern_str:
        sub = "sub" + (pump_char * max(1, length - 20))
        adversarial_string = f"http://{sub}.example{mismatch_char}"
        benign_string = f"http://{sub}.example.com/api"
    # General pump
    else:
        prefix_len = max(1, length - 1)
        adversarial_string = (pump_char * prefix_len) + mismatch_char
        benign_string = pump_char * length

    return adversarial_string, benign_string

if __name__ == "__main__":
    tests = [
        r"^(a+)+$",
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        r"^https?:\/\/.*$",
        r"^([0-9]+)+$"
    ]
    for t in tests:
        adv, ben = generate_adversarial_payload(t, 25)
        print(f"Regex: {t}")
        print(f"  Adv (len {len(adv)}): {adv[:30]}...")
        print(f"  Ben (len {len(ben)}): {ben[:30]}...")
