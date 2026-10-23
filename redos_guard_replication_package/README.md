# ReDoS-Guard: Characterizing the Catastrophic Backtracking Cliff

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Engines: CPython | regex | re2](https://img.shields.io/badge/Engines-CPython%20%7C%20regex%20%7C%20re2-orange.svg)](https://github.com/google/re2)


> **A Large-Scale Empirical Study of Algorithmic Complexity Breakdown in Production Regular Expression Engines**  
> **Authors:** Adarsh Singh, Devarsh Patel and Dr. Umamaheswari M  
> **Institution:** School of Computer Science & Engineering, Vellore Institute of Technology (VIT), Vellore, Tamil Nadu, 632014, India  
> **Correspondence:** `adarsh.singh2024b@vitstudent.ac.in`,`devarsh.patel2024@vitstudent.ac.in`, `umamaheswari.m@vit.ac.in`

---

## 📌 Overview

**ReDoS-Guard** is an open-source empirical benchmarking harness, complexity classification framework, and replication package designed to investigate **algorithmic complexity collapse** (Regular Expression Denial of Service — ReDoS) across production regular expression engines.

While theoretical automata admit linear-time Deterministic Finite Automaton (DFA) scanning, production programming runtimes (CPython `re`, Google V8 `Irregexp`, Java `java.util.regex`, PCRE2) evaluate regular expressions using **backtracking Non-Deterministic Finite Automata (NFAs)** to support non-regular extensions (backreferences, lookaround assertions). When evaluating adversarial inputs on patterns with nested quantifiers or overlapping alternations, backtracking NFAs experience combinatorial explosion, shifting from $\mathcal{O}(n)$ to polynomial $\mathcal{O}(n^d)$ or catastrophic exponential $\mathcal{O}(2^n)$ worst-case time complexity.

This repository contains the complete empirical evaluation pipeline, raw microsecond telemetry datasets, curve fitting algorithms, and publication figure generators evaluating **1,200 systematically sampled production patterns** (spanning 54,000 engine runs across CPython `re`, Python `regex`, and Google `re2`).

---

## 🔬 Key Empirical Findings

1. **Prevalence across Corpora (RQ1):**
   - Enterprise web validation regexes (RegexLib) remain overwhelmingly linear: **99.9%** execute in strictly $\mathcal{O}(n)$ time.
   - In contrast, **79.0%** of security benchmark patterns encounter exponential cliffs ($\mathcal{O}(2^n)$) and **1.0%** exhibit polynomial explosion.
   - Across the composite 1,200-pattern suite: **86.92%** linear, **12.92%** exponential, and **0.17%** polynomial ($N = 2$).

2. **Catastrophic Halting Horizon (RQ2):**
   - Exponential patterns breach an 800 ms watchdog limit at a median input pump of just $n^* = 36.1$ iterations (mean $76.05 \pm 93.88$, minimum $n^* = 22.6$).
   - This corresponds to a median payload length of $L^* = 41.8$ characters ($L^*_{\min} = 29.6$ characters), easily evading Web Application Firewall (WAF) size thresholds (typically 1,024–8,192 bytes).

3. **DFA Linearization via Google re2 (RQ3):**
   - **91.92%** (1,103/1,200) of production patterns compile and execute natively in Google `re2` without syntax errors.
   - Under adversarial workloads, linear engine substitution achieves $>10^5\times$ speedups without sacrificing web compatibility.

4. **Static Checker Ground-Truth Audit (RQ4):**
   - Heuristic static AST linters (e.g., `safe-regex`) suffer a **47.17% False Discovery Rate (FDR)** due to insensitivity to character class disjointness.
   - ReDoS-Guard's hybrid parametric regression achieves **99.42% accuracy**, **1.92% FDR**, and **0.29% FPR**.

---

## 📁 Repository Structure

```
├── benchmarks/                                # Benchmark regex corpora
│   ├── benchmark_regexes_1200.json            # Audited 1,200 evaluation patterns with AST metadata
│   ├── master_regex_corpus_10000.csv          # Stratified master corpus of 10,000 production patterns
│   ├── regexlib/                              # Enterprise web validation patterns (RegexLib)
│   ├── package_manifests/                     # High-impact npm & PyPI production expressions
│   └── owasp_cve/                             # Corroborated CVE & OWASP security benchmarks
├── results/                                   # Telemetry datasets & experimental findings
│   ├── metrics/
│   │   ├── raw_telemetry.csv                  # 18,000 pattern-length measurement points (54k runs)
│   │   ├── telemetry_raw_18000.csv            # Telemetry trace archive (CPython, regex, re2)
│   │   ├── big_o_classifications.csv          # OLS complexity degrees, R², and empirical classes
│   │   ├── fitted_models.parquet              # Parquet serialized regression model parameters
│   │   ├── halting_thresholds.csv             # Closed-form n* and L* halting inflection metrics
│   │   ├── engine_comparison.csv              # Paired latency ratios and speedup divergence
│   │   ├── confusion_matrix.csv               # Ground-truth confusion matrix for static analyzers
│   │   ├── static_checker_roc_metrics.json    # ROC and precision-recall metrics (safe-regex vs. Regexploit)
│   │   └── rq_statistical_summary.json        # Descriptive & non-parametric statistical summary
│   └── figures/                               # Publication-grade vector (PDF) and PNG figures
│       ├── fig1_complexity_distribution.pdf   # RQ1: Complexity distribution across corpora
│       ├── fig2_halting_threshold_cdf.pdf     # RQ2: Empirical ECDF of catastrophic halting thresholds
│       ├── fig3_latency_growth_curves.pdf     # Microsecond OLS growth curves vs. input length
│       ├── fig4_engine_divergence_speedup.pdf # RQ3: Google re2 vs. CPython re speedup ratio
│       ├── fig5_static_checker_roc_matrix.pdf # RQ4: Static AST checker confusion matrix
│       └── fig6_gap_taxonomy_clustering.pdf   # Research gap taxonomy clustering
├── src/                                       # Core implementation & benchmarking pipeline
│   ├── automata_analyzer.py                   # NFA transition analysis, cycle detection & star height
│   ├── adversarial_generator.py               # AST-guided adversarial pump string synthesizer
│   ├── adversarial_synthesizer.py             # CLI entrypoint for attack payload generation
│   ├── engine_benchmarker.py                  # High-precision multi-engine microsecond timing harness
│   ├── re2_verifier.py                        # CLI entrypoint for multi-engine speedup audits
│   ├── complexity_fitter.py                   # Ordinary Least Squares (OLS) power-law & semi-log regression
│   ├── static_checker_eval.py                 # Ground-truth accuracy, ROC/PR evaluation of AST linters
│   ├── regex_corpus_loader.py                 # Corpus sampling, deduplication, and schema validation
│   └── visualizer.py                          # Vectorized figure generation pipeline
├── literature/                                # Mined literature intelligence
│   ├── granular_gaps_and_scopes.csv           # Mined research gaps and limitations from 2024-2026
│   ├── harvested_papers.json                  # Bibliographic dataset of surveyed literature
│   ├── papers_2024_2026.bib                   # BibTeX collection of related automata/ReDoS literature
│   └── systematic_gap_taxonomy.md             # Gap taxonomy and resolution matrix
├── requirements.txt                           # Python dependencies
├── LICENSE                                    # MIT License
└── README.md                                  # Repository documentation
```

---

## 🚀 Quickstart & Installation

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.11 and 3.12)
- Linux (Ubuntu 22.04 LTS recommended) / macOS / Windows
- `gcc` / `g++` (required for compiling Google `re2` C++ bindings)

### 2. Environment Setup
```bash
# Clone the repository
git clone https://github.com/your-username/redos-guard.git
cd redos-guard

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install required packages
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 📊 Reproduction Workflow

### Step 1: Ingest & Sample Evaluation Corpora
Load and stratify the 1,200 evaluated regular expressions across RegexLib (1,000), npm/PyPI packages (100), and OWASP/CVE benchmarks (100):
```bash
python src/regex_corpus_loader.py
```

### Step 2: Run Multi-Engine Microsecond Benchmarking (RQ1–RQ3)
Execute patterns across CPython `re`, Python `regex`, and Google `re2` across input lengths $n \in [2, 30]$ with the 800 ms watchdog timeout:
```bash
python src/engine_benchmarker.py
```
*Note: Full execution across 54,000 runs requires ~35–45 minutes on a modern multi-core CPU.*

### Step 3: Fit Asymptotic Big-O Complexity Curves (RQ1–RQ2)
Perform Ordinary Least Squares (OLS) regression against power-law ($\mathcal{O}(n^d)$) and semi-log ($\mathcal{O}(2^n)$) models to calculate empirical complexity classes and halting inflection thresholds ($n^*, L^*$):
```bash
python src/complexity_fitter.py
```

### Step 4: Evaluate Static Checkers Against Dynamic Ground Truth (RQ4)
Benchmark static AST heuristic detectors (`safe-regex`, `Regexploit`) against microsecond runtime telemetry:
```bash
python src/static_checker_eval.py
```

### Step 5: Regenerate Publication Figures
Render publication-grade vector PDF and PNG charts in `results/figures/`:
```bash
python src/visualizer.py
```

---

## 🛠 Interactive Tools & CLI Usage

### Synthesize Adversarial Attack String for Any Regex
```bash
python src/adversarial_synthesizer.py --pattern "^([a-zA-Z0-9_.-]+)+$" --length 35
```

### Benchmark Any Regex Across Multi-Engine Runtimes
```bash
python src/re2_verifier.py --pattern "^([a-zA-Z0-9]+)+$" --length 24
```

---


- **License:** MIT Open Source License

---

## 📖 Citation

If you use ReDoS-Guard in your research, please cite:

```bibtex
@inproceedings{SinghPatelRedosGuard,
  author    = {Adarsh Singh, Devarsh Patel and Umamaheswari M},
  title     = {Characterizing the Catastrophic Backtracking Cliff: A Large-Scale Empirical Study of Algorithmic Complexity Breakdown in Production Regular Expression Engines},
  year      = {2026},
}
```

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
