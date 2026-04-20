<div align="center">

<img src="docs/images/Screenshot 2026-04-12 213615.png" alt="BAYREUTHWING — Autonomous Security Intelligence Platform" width="100%">

<br/>

# BAYREUTHWING v2.0 — Mythos-Class Engine

**An autonomous, self-evolving security intelligence platform that thinks like an attacker.**

BAYREUTHWING combines a 100M-parameter CodeTransformer neural network with 10 specialized analysis engines — including cognitive reasoning, adversarial simulation, and self-evolution — to deliver autonomous, continuously-improving vulnerability detection across 35 vulnerability classes mapped to OWASP Top 10 and 50+ CWE standards.

<br/>

[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.0%2B-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)](https://pytorch.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-black?style=for-the-badge)](https://owasp.org/Top10/)
[![Parameters](https://img.shields.io/badge/Model-100M%20Params-purple?style=for-the-badge)](.)
[![Vulns](https://img.shields.io/badge/Vuln%20Classes-35-red?style=for-the-badge)](.)
[![Engines](https://img.shields.io/badge/Analysis%20Engines-10-blue?style=for-the-badge)](.)

</div>

---

<!-- GitHub Topics: ai, security, vulnerability-scanner, code-analysis, pytorch, transformer, owasp, cwe, sast, static-analysis, deep-learning, cybersecurity, code-security, machine-learning, defensive-security, adversarial-simulation, self-evolution, cognitive-reasoning -->

## Table of Contents

- [Overview](#overview)
- [What Makes This Mythos-Class](#what-makes-this-mythos-class)
- [Architecture](#architecture)
- [The 10 Analysis Engines](#the-10-analysis-engines)
- [Vulnerability Coverage](#vulnerability-coverage)
- [Intelligence Layers](#intelligence-layers)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Self-Evolution](#self-evolution)
- [Internet Intelligence](#internet-intelligence)
- [Admin Controls](#admin-controls)
- [Configuration](#configuration)
- [Testing](#testing)
- [Disclaimer](#disclaimer)

---

## Overview

BAYREUTHWING v2.0 is not a vulnerability scanner — it is an **autonomous security intelligence platform** that:

- **Thinks** — Correlates findings across files, builds attack narratives, identifies what it DIDN'T check
- **Attacks** — Simulates 5 threat actor profiles (Script Kiddie → APT) against your code using MITRE ATT&CK kill chains
- **Learns** — Gets better with every scan by discovering new vulnerability patterns and auto-tuning detection strategies
- **Discovers** — Connects to NVD/CVE databases to research zero-day threats and enrich findings with real-world intelligence
- **Evolves** — Autonomously generates new detection rules from scan data without human intervention

The system operates as a **10-engine multi-agent architecture** where specialized analysis modules collaborate, reason, and self-improve:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                      BAYREUTHWING v2.0 — MYTHOS-CLASS                      │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│  │   ML     │ │  Static  │ │  Code    │ │  Reverse │ │ Dynamic  │         │
│  │ 100M     │ │  Rules   │ │  Flow    │ │  Engrng  │ │  Rules   │         │
│  │ Params   │ │  200+    │ │ Analysis │ │  5 Mods  │ │  30+     │         │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘         │
│       └────────────┼────────────┼────────────┼────────────┘               │
│              ┌─────▼────────────▼────────────▼──────┐                     │
│              │     Finding Merger & Deduplicator     │                     │
│              └─────┬────────────────────────────────┘                     │
│              ┌─────▼────────────────────────────────┐                     │
│              │     MiroFish Deep Scan Engine         │   ← Multi-dim      │
│              │     18+ Strategy Handlers             │     scenario exec   │
│              └─────┬────────────────────────────────┘                     │
│              ┌─────▼────────────────────────────────┐                     │
│              │     Cognitive Reasoning Engine        │   ← Attack path     │
│              │     Cross-file correlation + Blind    │     synthesis        │
│              │     spot detection                    │                     │
│              └─────┬────────────────────────────────┘                     │
│              ┌─────▼────────────────────────────────┐                     │
│              │     Adversarial Simulation Engine     │   ← MITRE ATT&CK   │
│              │     5 Threat Actor Profiles           │     kill chains      │
│              └─────┬────────────────────────────────┘                     │
│              ┌─────▼────────────────────────────────┐                     │
│              │     Self-Evolution Engine             │   ← Autonomous      │
│              │     Pattern discovery + Auto-tune     │     improvement     │
│              └─────┬────────────────────────────────┘                     │
│              ┌─────▼────────────────────────────────┐                     │
│              │     Internet Discovery (Optional)     │   ← NVD/CVE        │
│              │     Zero-day research + Enrichment    │     zero-day        │
│              └──────────────────────────────────────┘                     │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## What Makes This Mythos-Class

| Capability | Traditional SAST | ML Scanners | **BAYREUTHWING v2.0** |
|---|---|---|---|
| Pattern Matching | ✓ Regex rules | ✓ Neural patterns | ✓ **200+ rules + 100M neural + self-evolved** |
| Cross-File Analysis | ✗ | ✗ | ✓ **Cognitive correlation across entire codebase** |
| Attack Simulation | ✗ | ✗ | ✓ **5 threat actor profiles + MITRE ATT&CK kill chains** |
| Self-Improvement | ✗ | ✗ | ✓ **Autonomous pattern discovery + strategy evolution** |
| Blind Spot Detection | ✗ | ✗ | ✓ **Meta-cognition identifies what WASN'T checked** |
| Threat Narratives | ✗ | ✗ | ✓ **Executive-ready attack stories with mitigations** |
| Zero-Day Research | ✗ | ✗ | ✓ **Internet-connected NVD/CVE/OSV intelligence** |
| Multi-Dimensional Scan | ✗ | ✗ | ✓ **8 vulnerability dimensions × 10 compound chains** |
| Adaptive Learning | ✗ | Partial | ✓ **Persistent memory across scans with decay** |
| Vulnerability Classes | 10-15 | 10-20 | **35 classes covering ALL known vulnerability families** |

---

## The 10 Analysis Engines

### 1. ML Inference Engine (100M Parameters)
The CodeTransformer neural network with vulnerability-focused attention mechanism. 768-dimensional embeddings, 12 transformer layers, 12 attention heads.

### 2. Static Rules Engine (200+ Rules)
Curated regex patterns for known vulnerability signatures across Python, JavaScript, Java, Go, PHP, Ruby, C#, and Rust.

### 3. Code Flow Analyzer
Taint tracking, dangerous function detection, missing security controls, and data flow analysis.

### 4. Reverse Engineering Analyzer
Five specialized modules: Binary Inspector, API Inferencer, Endpoint Discoverer, Hidden Route Detector, and Decompiled Logic Analyzer.

### 5. Dynamic Rules Engine (30+ Hot-Loadable Rules)
Self-tuning rules with per-rule effectiveness tracking. Auto-disables high-FP rules, auto-promotes high-TP rules. Hot-reloads from config files.

### 6. MiroFish Deep Scan Engine
Multi-dimensional scenario execution across 8 vulnerability dimensions with 18+ concrete strategy handlers. Includes compound vulnerability chain detection (10 chains) and 40+ mutation pathways.

### 7. Cognitive Reasoning Engine
Meta-cognitive analysis that correlates findings across files, synthesizes attack paths, detects blind spots, calibrates confidence, and generates executive-level threat narratives.

### 8. Adversarial Simulation Engine
Simulates 5 threat actor profiles (Script Kiddie → APT) using MITRE ATT&CK kill chains. Models reconnaissance through exfiltration with countermeasure recommendations.

### 9. Self-Evolution Engine
Autonomous pattern discovery from scan data. Extracts code patterns, validates through confirmation, promotes or retires based on precision, and tracks improvement velocity.

### 10. Internet Discovery Engine
Connects to NVD, OSV.dev, and other sources to research suspicious patterns, enrich findings with real-world CVE data, and generate detection rules from trending vulnerabilities.

---

## Vulnerability Coverage

### 35 Vulnerability Classes

| ID | Vulnerability | CWE | OWASP | Severity |
|----|--------------|-----|-------|----------|
| 0 | SQL Injection | CWE-89 | A03:2021 | Critical |
| 1 | Cross-Site Scripting (XSS) | CWE-79 | A03:2021 | High |
| 2 | Command Injection | CWE-78 | A03:2021 | Critical |
| 3 | Insufficient Input Validation | CWE-20 | A03:2021 | Medium |
| 4 | Broken Access Control | CWE-284 | A01:2021 | Critical |
| 5 | Cryptographic Failures | CWE-327 | A02:2021 | High |
| 6 | Security Misconfiguration | CWE-16 | A05:2021 | Medium |
| 7 | Sensitive Data Exposure | CWE-200 | A02:2021 | High |
| 8 | Insecure Deserialization | CWE-502 | A08:2021 | Critical |
| 9 | Insufficient Logging | CWE-778 | A09:2021 | Low |
| 10 | Path Traversal | CWE-22 | A01:2021 | High |
| 11 | Using Known Vuln Components | CWE-1104 | A06:2021 | High |
| 12 | Server-Side Template Injection | CWE-1336 | A03:2021 | Critical |
| 13 | XML External Entity (XXE) | CWE-611 | A05:2021 | High |
| 14 | JWT Vulnerabilities | CWE-347 | A02:2021 | Critical |
| 15 | Mass Assignment | CWE-915 | A04:2021 | High |
| 16 | Insecure Direct Object Ref | CWE-639 | A01:2021 | High |
| 17 | Server-Side Request Forgery | CWE-918 | A10:2021 | Critical |
| 18 | Open Redirect | CWE-601 | A01:2021 | Medium |
| 19 | Information Disclosure | CWE-209 | A05:2021 | Medium |
| 20 | CORS Misconfiguration | CWE-942 | A05:2021 | High |
| 21 | Prototype Pollution | CWE-1321 | A03:2021 | High |
| 22 | Race Condition | CWE-362 | A04:2021 | High |
| 23 | Unrestricted File Upload | CWE-434 | A04:2021 | Critical |
| 24 | ReDoS | CWE-1333 | A06:2021 | Medium |
| 25 | Log Injection | CWE-117 | A09:2021 | Medium |
| 26 | CRLF Injection | CWE-93 | A03:2021 | Medium |
| 27 | HTTP Header Injection | CWE-113 | A03:2021 | Medium |
| 28 | Business Logic Flaws | CWE-840 | A04:2021 | High |
| 29 | Integer Overflow | CWE-190 | A03:2021 | High |
| 30 | Dependency Confusion | CWE-427 | A06:2021 | Critical |
| 31 | Vulnerable Dependencies | CWE-1104 | A06:2021 | High |
| 32 | Insecure Default Config | CWE-276 | A05:2021 | Medium |
| 33 | LDAP Injection | CWE-90 | A03:2021 | High |
| 34 | XPath Injection | CWE-643 | A03:2021 | High |

---

## Intelligence Layers

### Cognitive Reasoning
```
Inputs: Raw findings from all scanners
   │
   ├── Cross-File Correlation → Finds vulnerability chains across files
   ├── Attack Path Synthesis → Builds realistic exploitation sequences
   ├── Blind Spot Detection → Identifies unchecked attack surfaces
   ├── Impact Amplification → Elevates severity when vulns combine
   ├── Confidence Calibration → Meta-cognitive accuracy adjustment
   └── Threat Narratives → Executive-ready attack stories
```

### Adversarial Simulation
```
Threat Actor Profiles:
   ├── Script Kiddie      → Public tools, 1 hour budget
   ├── Opportunist        → Custom scripts, 8 hour budget
   ├── Professional       → Custom exploits, 40 hour budget
   ├── Organized Crime    → Team attacks, ransomware, 200 hours
   └── APT (Nation-State) → Zero-days, year-long campaigns

Kill Chain (MITRE ATT&CK):
   Reconnaissance → Initial Access → Execution → Persistence
   → Privilege Escalation → Defense Evasion → Credential Access
   → Discovery → Lateral Movement → Collection → Exfiltration → Impact
```

### Self-Evolution
```
Scan Results
   │
   ├── Pattern Extraction → Discover new vuln patterns from code
   ├── Pattern Validation → Confirm patterns across multiple scans
   ├── Pattern Promotion → Activate patterns with 60%+ precision
   ├── Pattern Retirement → Retire patterns with >60% FP rate
   ├── Strategy Evolution → Auto-tune strategy priorities
   └── Velocity Tracking → Measure improvement over time
```

---

## Project Structure

```
BayreuthWing/
├── config/
│   └── model_config.yaml         # 100M-param model + all engine configs
├── src/
│   ├── model/
│   │   ├── transformer.py        # CodeTransformer (100M parameters)
│   │   ├── attention.py          # Multi-head + Vulnerability attention
│   │   ├── embeddings.py         # Positional + token-type embeddings
│   │   └── tokenizer.py          # Code-aware tokenizer
│   ├── scanner/
│   │   ├── engine.py             # Mythos-class 10-engine orchestrator
│   │   ├── rules.py              # 200+ static analysis rules
│   │   ├── analyzer.py           # Code flow analysis
│   │   ├── dynamic_rules.py      # Hot-loadable self-tuning rules
│   │   ├── cognitive_engine.py   # Cognitive reasoning + attack paths
│   │   ├── adversarial_sim.py    # MITRE ATT&CK adversarial simulation
│   │   ├── self_evolution.py     # Autonomous pattern evolution
│   │   └── reversing/
│   │       ├── mirofish.py       # MiroFish scenario engine
│   │       ├── scenario_executor.py  # 18+ strategy handlers
│   │       ├── adaptive_learning.py  # Persistent learning memory
│   │       ├── analyzer.py       # Reverse engineering orchestrator
│   │       ├── binary_inspector.py
│   │       ├── api_inferencer.py
│   │       ├── endpoint_discoverer.py
│   │       ├── hidden_route_detector.py
│   │       └── decompiled_logic_analyzer.py
│   ├── intel/
│   │   ├── vuln_discovery.py     # Internet-connected zero-day research
│   │   ├── threat_feed.py        # CISA KEV + OSV.dev feeds
│   │   ├── cve_client.py         # NVD/CVE API client
│   │   ├── dependency_checker.py # SCA + SBOM analysis
│   │   └── github_scanner.py     # GitHub secret/config scanning
│   ├── training/                 # Model training pipeline
│   └── utils/
│       ├── cwe_mapping.py        # 35-class CWE/OWASP mapping
│       ├── helpers.py            # File utilities
│       └── logger.py             # Structured logging
├── tests/                        # Comprehensive test suite
├── cli.py                        # Command-line interface
├── requirements.txt
└── README.md
```

---

## Installation

```bash
# Clone
git clone https://github.com/apocalypse9949/BayreuthWing.git
cd BayreuthWing

# Setup virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Basic Scan
```bash
# Scan a directory
python cli.py scan /path/to/code

# Scan a single file
python cli.py scan /path/to/file.py
```

### Deep Scan (MiroFish + All Engines)
```bash
# Enable full Mythos-class analysis
python cli.py scan /path/to/code --deep

# Enable adversarial simulation
python cli.py scan /path/to/code --deep --adversarial

# Enable internet discovery
python cli.py scan /path/to/code --deep --discover
```

### Intelligence Reports
```bash
# View adaptive learning stats
python cli.py adaptive-report

# View self-evolution report
python cli.py evolution-report

# View MiroFish stats
python cli.py mirofish-stats
```

### Output Formats
```bash
# JSON output
python cli.py scan /path/to/code --format json --output report.json

# HTML report
python cli.py scan /path/to/code --format html --output report.html

# SARIF (for CI/CD integration)
python cli.py scan /path/to/code --format sarif --output report.sarif
```

---

## Self-Evolution

BayreuthWing autonomously improves with every scan:

1. **Pattern Extraction** — Analyzes matched code to discover recurring vulnerability patterns
2. **Confirmation Tracking** — Counts how many scans confirm each pattern (min 3 to activate)
3. **Precision Monitoring** — Tracks true positive vs false positive rates
4. **Automatic Promotion** — Patterns with ≥60% precision become active detection rules
5. **Automatic Retirement** — Patterns with >60% FP rate are deactivated
6. **Age Decay** — Patterns not confirmed in 90 days are retired
7. **Velocity Tracking** — Measures detection improvement rate over time

**Persistent State:** Evolution data is stored in `~/.bayreuthwing/evolution_state.json`

---

## Internet Intelligence

When enabled (`--discover` flag), BayreuthWing connects to:

| Source | Purpose |
|--------|---------|
| **NVD (NIST)** | CVE details, CVSS scores, affected products |
| **OSV.dev** | Open-source vulnerability database |
| **CISA KEV** | Known Exploited Vulnerabilities catalog |

**Security:** Internet discovery is disabled by default and requires explicit activation. All queries are rate-limited and cached.

---

## Admin Controls

### Disabling Modules

In `config/model_config.yaml`:

```yaml
scanner:
  modules:
    code_analysis:
      enabled: false    # Disable static rules
    architecture_analysis:
      enabled: false    # Disable code flow

# Disable internet discovery globally
internet_discovery:
  enabled: false
```

### Confidence Tuning

```yaml
scanner:
  confidence_threshold: 0.5  # Adjust sensitivity (0.0 - 1.0)
  severity:
    critical_threshold: 0.8
    high_threshold: 0.6
    medium_threshold: 0.4
```

---

## Configuration

The central configuration file is `config/model_config.yaml`:

```yaml
model:
  architecture:
    vocab_size: 50000
    embedding_dim: 768        # 100M-parameter configuration
    num_layers: 12
    num_heads: 12
    feedforward_dim: 3072
    max_sequence_length: 2048
    dropout: 0.1
    num_vulnerability_classes: 35

mirofish:
  max_iterations: 15
  max_scenarios_per_scan: 100
  dimensions: [injection, authentication, cryptography, logic, data_flow, network, supply_chain, serialization]
  enable_compound_chains: true

adaptive_learning:
  state_dir: "~/.bayreuthwing"
  recency_decay_days: 30
  max_scan_memories: 100

dynamic_rules:
  auto_tune: true
  max_fp_rate_before_disable: 0.6
  min_tp_rate_for_promote: 0.7
  hot_reload: true

internet_discovery:
  enabled: false
  rate_limit_per_minute: 10
  cache_ttl_hours: 24
```

---

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Test model instantiation (100M params)
python -m pytest tests/test_model.py -v

# Test cognitive engine
python -m pytest tests/test_cognitive.py -v

# Test adversarial simulation
python -m pytest tests/test_adversarial.py -v
```

---

## Anti-Hallucination Safeguards

Every component in BayreuthWing is designed to prevent false results:

- **Enum-Bounded Strategies** — All MiroFish strategies come from a finite StrategyType enum
- **Deterministic Handlers** — All 18+ scenario handlers use regex/AST analysis, not generative AI
- **Provenance Chains** — Every finding traces back to source code + generating rule
- **Confidence Calibration** — Meta-cognitive layer adjusts confidence against historical accuracy
- **Template-Based Narratives** — All threat narratives use structured templates, not LLM generation
- **Bounded Evolution** — Self-evolution is capped at 500 patterns with mandatory precision thresholds

---

## Disclaimer

**BAYREUTHWING is designed for authorized security testing and defensive purposes only.**

- Obtain proper authorization before scanning any system
- Use findings to improve security, not exploit vulnerabilities
- Internet discovery queries public databases (NVD, OSV) — no active exploitation
- The ML model makes predictions based on code patterns — always verify findings

This tool is provided "as is" for educational and research purposes. The authors are not responsible for misuse.

---

<div align="center">

**Built with 🔒 for the security community**

*BAYREUTHWING v2.0 — Mythos-Class Autonomous Security Intelligence*

</div>
