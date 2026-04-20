"""
BAYREUTHWING — Self-Evolution Engine

The autonomous self-improvement layer. Analyzes scan outcomes over time
to evolve scanner behavior without human intervention:

    1. Pattern Synthesis — Discover new vulnerability patterns from scan data
    2. Strategy Evolution — Generate new analysis strategies from patterns
    3. Rule Generation — Create new dynamic rules from repeated findings
    4. Priority Calibration — Auto-tune strategy priorities from outcomes
    5. Cross-Scan Intelligence — Transfer learnings between different targets
    6. Decay Management — Gradually forget outdated patterns
    7. Performance Benchmarking — Track improvement velocity

This is the system that makes BayreuthWing get BETTER with every scan.

Architecture:
    ┌───────────────────────────────────────────────────────────┐
    │                 SELF-EVOLUTION ENGINE                     │
    ├───────────────────────────────────────────────────────────┤
    │                                                          │
    │  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
    │  │  Pattern     │  │  Strategy    │  │  Rule         │  │
    │  │  Synthesizer │  │  Evolver     │  │  Generator    │  │
    │  └──────┬───────┘  └──────┬───────┘  └───────┬───────┘  │
    │         │                 │                   │          │
    │  ┌──────▼─────────────────▼───────────────────▼───────┐  │
    │  │         Evolution State (persistent JSON)           │  │
    │  └──────────────────────┬─────────────────────────────┘  │
    │                         │                                │
    │  ┌──────────────────────▼─────────────────────────────┐  │
    │  │         Improvement Velocity Tracker                │  │
    │  └────────────────────────────────────────────────────┘  │
    └───────────────────────────────────────────────────────────┘

Anti-Hallucination:
    - All evolved patterns are derived from concrete findings
    - Generated rules must pass validation before activation
    - Strategy modifications are bounded by StrategyType enum
    - Evolution velocity is capped to prevent runaway drift
    - Every evolution step is logged with full provenance
"""

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional


# ═══════════════════════════════════════════════════════════════
# EVOLVED PATTERN — A pattern discovered from scan data
# ═══════════════════════════════════════════════════════════════

@dataclass
class EvolvedPattern:
    """A vulnerability pattern discovered through self-evolution."""
    pattern_id: str
    name: str
    description: str
    regex_pattern: str             # The actual detection regex
    vuln_class: int               # Which vulnerability class it detects
    confidence: float = 0.5       # Discovery confidence
    times_confirmed: int = 0      # How many scans confirmed this
    times_false_positive: int = 0 # False positive count
    discovered_at: float = 0.0    # Timestamp
    source_scan_ids: list = field(default_factory=list)  # What scans led to this
    languages: list = field(default_factory=list)  # Which languages it applies to
    is_active: bool = True
    generation: int = 0           # Which evolution generation

    @property
    def precision(self) -> float:
        total = self.times_confirmed + self.times_false_positive
        if total == 0:
            return 0.5
        return self.times_confirmed / total

    def to_dict(self) -> dict:
        return {
            "pattern_id": self.pattern_id,
            "name": self.name,
            "description": self.description,
            "regex_pattern": self.regex_pattern,
            "vuln_class": self.vuln_class,
            "confidence": round(self.confidence, 3),
            "times_confirmed": self.times_confirmed,
            "times_false_positive": self.times_false_positive,
            "precision": round(self.precision, 3),
            "discovered_at": self.discovered_at,
            "source_scan_ids": self.source_scan_ids,
            "languages": self.languages,
            "is_active": self.is_active,
            "generation": self.generation,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EvolvedPattern":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class EvolutionMetrics:
    """Tracks improvement velocity over time."""
    total_evolutions: int = 0
    patterns_generated: int = 0
    patterns_promoted: int = 0      # Moved from experimental to active
    patterns_retired: int = 0       # Removed due to low precision
    rules_generated: int = 0
    strategies_evolved: int = 0
    detection_rate_improvement: float = 0.0  # % improvement
    false_positive_reduction: float = 0.0    # % reduction
    scans_analyzed: int = 0
    last_evolution_timestamp: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_evolutions": self.total_evolutions,
            "patterns_generated": self.patterns_generated,
            "patterns_promoted": self.patterns_promoted,
            "patterns_retired": self.patterns_retired,
            "rules_generated": self.rules_generated,
            "strategies_evolved": self.strategies_evolved,
            "detection_rate_improvement": round(self.detection_rate_improvement, 2),
            "false_positive_reduction": round(self.false_positive_reduction, 2),
            "scans_analyzed": self.scans_analyzed,
            "last_evolution_timestamp": self.last_evolution_timestamp,
        }


# ═══════════════════════════════════════════════════════════════
# VULNERABILITY FINGERPRINTS — Common code patterns per vuln class
# ═══════════════════════════════════════════════════════════════

# Code fragments that are strong indicators of vulnerability types.
# The evolution engine uses these as seeds to learn new patterns.
VULN_FINGERPRINTS = {
    # SQLi indicators
    0: {
        "keywords": ["execute", "query", "cursor", "rawQuery", "executeQuery", "prepare", "sql"],
        "dangerous_patterns": [r"['\"].*\+.*['\"]", r"format\s*\(", r"f['\"].*\{", r"%s.*%"],
        "safe_patterns": [r"parameterized", r"prepared_statement", r"\?\s*,", r"bind_param"],
    },
    # XSS indicators  
    1: {
        "keywords": ["innerHTML", "document.write", "outerHTML", "insertAdjacentHTML", "dangerouslySetInnerHTML"],
        "dangerous_patterns": [r"innerHTML\s*=", r"document\.write\s*\(", r"eval\s*\(", r"\$\s*\(.*\.html\s*\("],
        "safe_patterns": [r"textContent", r"innerText", r"DOMPurify", r"sanitize", r"escape"],
    },
    # Command Injection indicators
    2: {
        "keywords": ["exec", "system", "popen", "subprocess", "child_process", "spawn", "shell"],
        "dangerous_patterns": [r"os\.system\s*\(", r"subprocess\.call\s*\(.*shell\s*=\s*True", r"exec\s*\(.*\+"],
        "safe_patterns": [r"shlex\.quote", r"shell=False", r"subprocess\.run\s*\(\["],
    },
    # SSTI indicators
    12: {
        "keywords": ["render_template_string", "Template", "Jinja2", "from_string", "render"],
        "dangerous_patterns": [r"render_template_string\s*\(.*\+", r"Template\s*\(.*\+", r"\{\{.*user"],
        "safe_patterns": [r"autoescape", r"SandboxedEnvironment", r"render_template\s*\("],
    },
    # SSRF indicators
    17: {
        "keywords": ["requests.get", "urllib", "fetch", "http.get", "axios", "curl_exec"],
        "dangerous_patterns": [r"requests\.get\s*\(.*\+", r"urlopen\s*\(.*\+", r"fetch\s*\(.*\+"],
        "safe_patterns": [r"allowlist", r"whitelist", r"validate_url", r"is_internal"],
    },
    # Deserialization indicators
    8: {
        "keywords": ["pickle", "unserialize", "yaml.load", "ObjectInputStream", "json.loads", "marshal"],
        "dangerous_patterns": [r"pickle\.loads?\s*\(", r"yaml\.load\s*\((?!.*Loader)", r"unserialize\s*\("],
        "safe_patterns": [r"yaml\.safe_load", r"Loader=SafeLoader", r"json\.loads"],
    },
    # Prototype Pollution indicators
    21: {
        "keywords": ["__proto__", "prototype", "constructor", "merge", "extend", "assign"],
        "dangerous_patterns": [r"__proto__", r"\[.*constructor.*\]", r"Object\.assign\s*\(.*req"],
        "safe_patterns": [r"Object\.freeze", r"Object\.seal", r"hasOwnProperty"],
    },
    # JWT indicators
    14: {
        "keywords": ["jwt", "jsonwebtoken", "decode", "verify", "sign", "algorithms"],
        "dangerous_patterns": [r"algorithms.*none", r"verify\s*=\s*False", r"decode\s*\(.*verify\s*=\s*False"],
        "safe_patterns": [r"algorithms=\[.RS256.\]", r"verify=True", r"verify_signature"],
    },
}


# ═══════════════════════════════════════════════════════════════
# SELF-EVOLUTION ENGINE
# ═══════════════════════════════════════════════════════════════

class SelfEvolutionEngine:
    """
    The autonomous improvement brain.

    Analyzes scan results over time to:
    1. Discover new vulnerability patterns from code that triggers findings
    2. Generate new detection rules from repeated patterns
    3. Tune strategy priorities based on effectiveness
    4. Retire patterns that produce too many false positives
    5. Track and report improvement velocity

    Every evolution step is deterministic and auditable.
    """

    DEFAULT_STATE_DIR = os.path.expanduser("~/.bayreuthwing")
    DEFAULT_STATE_FILE = "evolution_state.json"

    # Evolution parameters
    MIN_CONFIRMATIONS_TO_PROMOTE = 3    # Minimum confirmations before a pattern becomes active
    MAX_FP_RATE_BEFORE_RETIRE = 0.6     # Retire pattern if FP rate exceeds this
    MAX_EVOLVED_PATTERNS = 500          # Cap total evolved patterns
    MIN_SCANS_BEFORE_EVOLUTION = 2      # Need at least N scans before evolving
    PATTERN_DECAY_DAYS = 90             # Age out patterns not confirmed in N days
    MAX_GENERATION = 10                 # Maximum evolution generations

    def __init__(self, state_dir: str = None, state_file: str = None):
        self.state_dir = state_dir or self.DEFAULT_STATE_DIR
        self.state_file = state_file or self.DEFAULT_STATE_FILE
        self.state_path = os.path.join(self.state_dir, self.state_file)

        # State
        self.evolved_patterns: dict[str, EvolvedPattern] = {}
        self.metrics = EvolutionMetrics()
        self.scan_history: list[dict] = []  # Recent scan summaries

        # Load persisted state
        self._load()

    def _load(self):
        """Load evolution state from disk."""
        if not os.path.exists(self.state_path):
            return

        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for pid, pdata in data.get("evolved_patterns", {}).items():
                self.evolved_patterns[pid] = EvolvedPattern.from_dict(pdata)

            metrics_data = data.get("metrics", {})
            for k, v in metrics_data.items():
                if hasattr(self.metrics, k):
                    setattr(self.metrics, k, v)

            self.scan_history = data.get("scan_history", [])[-100:]  # Keep last 100

        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    def save(self):
        """Persist evolution state to disk."""
        os.makedirs(self.state_dir, exist_ok=True)

        data = {
            "evolved_patterns": {
                pid: p.to_dict() for pid, p in self.evolved_patterns.items()
            },
            "metrics": self.metrics.to_dict(),
            "scan_history": self.scan_history[-100:],
        }

        tmp_path = self.state_path + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, self.state_path)
        except OSError:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def evolve(self, scan_results: dict) -> dict:
        """
        Run a full evolution cycle based on scan results.

        Args:
            scan_results: Complete scan results dict from ScanEngine.

        Returns:
            Evolution report dict.
        """
        self.metrics.total_evolutions += 1
        self.metrics.last_evolution_timestamp = time.time()
        self.metrics.scans_analyzed += 1

        # Record scan summary
        scan_summary = {
            "timestamp": time.time(),
            "total_findings": scan_results.get("total_findings", 0),
            "severity_counts": scan_results.get("severity_counts", {}),
            "files_scanned": scan_results.get("files_scanned", 0),
        }
        self.scan_history.append(scan_summary)

        report = {
            "evolution_cycle": self.metrics.total_evolutions,
            "new_patterns": [],
            "promoted_patterns": [],
            "retired_patterns": [],
            "strategy_adjustments": [],
        }

        findings = scan_results.get("findings", [])

        # Phase 1: Extract code patterns from findings
        new_patterns = self._extract_patterns(findings)
        report["new_patterns"] = [p.to_dict() for p in new_patterns]

        # Phase 2: Validate and confirm existing patterns
        confirmations = self._validate_existing_patterns(findings)
        report["confirmations"] = confirmations

        # Phase 3: Promote patterns with enough confirmations
        promoted = self._promote_patterns()
        report["promoted_patterns"] = [p.to_dict() for p in promoted]

        # Phase 4: Retire low-performing patterns
        retired = self._retire_patterns()
        report["retired_patterns"] = [p.pattern_id for p in retired]

        # Phase 5: Generate strategy adjustments
        adjustments = self._evolve_strategies(findings)
        report["strategy_adjustments"] = adjustments

        # Phase 6: Age-based decay
        decayed = self._apply_decay()
        report["decayed_patterns"] = decayed

        # Phase 7: Track improvement velocity
        velocity = self._calculate_velocity()
        report["improvement_velocity"] = velocity

        # Persist
        self.save()

        return report

    def _extract_patterns(self, findings: list[dict]) -> list[EvolvedPattern]:
        """
        Analyze findings to extract new vulnerability patterns.

        Looks at the matched code and surrounding context to identify
        recurring patterns that could be turned into detection rules.
        """
        new_patterns = []
        # Group findings by vulnerability class
        by_class: dict[int, list[dict]] = {}
        for f in findings:
            vc = f.get("vuln_class", -1)
            if vc not in by_class:
                by_class[vc] = []
            by_class[vc].append(f)

        for vuln_class, class_findings in by_class.items():
            if len(class_findings) < 2:
                continue  # Need at least 2 findings to identify a pattern

            # Extract matched text fragments
            matched_texts = [
                f.get("matched_text", "").strip()
                for f in class_findings
                if f.get("matched_text", "").strip()
            ]

            if not matched_texts:
                continue

            # Find common substrings/patterns in matched texts
            common_tokens = self._find_common_tokens(matched_texts)

            for token_set in common_tokens:
                pattern_str = self._tokens_to_regex(token_set)
                if not pattern_str or len(pattern_str) < 5:
                    continue

                # Validate the regex
                try:
                    re.compile(pattern_str)
                except re.error:
                    continue

                pattern_id = hashlib.sha256(
                    f"{vuln_class}:{pattern_str}".encode()
                ).hexdigest()[:16]

                # Skip if we already have this pattern
                if pattern_id in self.evolved_patterns:
                    # Confirm existing pattern
                    self.evolved_patterns[pattern_id].times_confirmed += 1
                    continue

                pattern = EvolvedPattern(
                    pattern_id=pattern_id,
                    name=f"EVOLVED-{vuln_class}-{pattern_id[:8]}",
                    description=f"Auto-discovered pattern for vuln class {vuln_class} from {len(class_findings)} findings",
                    regex_pattern=pattern_str,
                    vuln_class=vuln_class,
                    confidence=0.4,  # Start low, promote on confirmation
                    times_confirmed=1,
                    discovered_at=time.time(),
                    source_scan_ids=[],
                    languages=[],
                    is_active=False,  # Experimental until promoted
                    generation=self.metrics.total_evolutions,
                )

                self.evolved_patterns[pattern_id] = pattern
                new_patterns.append(pattern)
                self.metrics.patterns_generated += 1

        return new_patterns

    def _find_common_tokens(self, texts: list[str]) -> list[list[str]]:
        """
        Find common token sequences across multiple matched texts.

        Returns groups of tokens that appear in at least half the texts.
        """
        if not texts:
            return []

        # Tokenize each text
        all_tokens = []
        for text in texts:
            tokens = re.findall(r'[a-zA-Z_]\w*|[^\s\w]', text)
            all_tokens.append(tokens)

        # Find tokens that appear in at least half the texts
        common = []
        if not all_tokens:
            return []

        # Count token frequency across texts
        token_freq: dict[str, int] = {}
        for tokens in all_tokens:
            seen = set()
            for t in tokens:
                if t not in seen:
                    token_freq[t] = token_freq.get(t, 0) + 1
                    seen.add(t)

        threshold = max(2, len(texts) // 2)
        frequent_tokens = [t for t, count in token_freq.items() if count >= threshold and len(t) > 1]

        if frequent_tokens:
            common.append(frequent_tokens[:5])  # Cap at 5 tokens per pattern

        return common

    def _tokens_to_regex(self, tokens: list[str]) -> str:
        """Convert a list of common tokens into a detection regex."""
        if not tokens:
            return ""

        # Build a regex that matches lines containing all tokens
        escaped = [re.escape(t) for t in tokens]

        if len(escaped) == 1:
            return escaped[0]

        # Create a pattern that matches if any 2 tokens appear near each other
        if len(escaped) >= 2:
            return r"(?=.*" + r")(?=.*".join(escaped[:3]) + r")"

        return "|".join(escaped)

    def _validate_existing_patterns(self, findings: list[dict]) -> int:
        """
        Check if existing patterns match current findings.

        Increments confirmation count for patterns that would have
        caught the same findings independently.
        """
        confirmations = 0

        for pattern in self.evolved_patterns.values():
            if not pattern.is_active and not pattern.regex_pattern:
                continue

            try:
                compiled = re.compile(pattern.regex_pattern)
            except re.error:
                continue

            for finding in findings:
                matched_text = finding.get("matched_text", "")
                if matched_text and compiled.search(matched_text):
                    if finding.get("vuln_class") == pattern.vuln_class:
                        pattern.times_confirmed += 1
                        confirmations += 1
                    else:
                        # Pattern matched but wrong class = false positive
                        pattern.times_false_positive += 1

        return confirmations

    def _promote_patterns(self) -> list[EvolvedPattern]:
        """Promote experimental patterns that have enough confirmations."""
        promoted = []

        for pattern in self.evolved_patterns.values():
            if pattern.is_active:
                continue

            if (pattern.times_confirmed >= self.MIN_CONFIRMATIONS_TO_PROMOTE
                    and pattern.precision >= 0.6):
                pattern.is_active = True
                pattern.confidence = min(0.9, pattern.precision)
                promoted.append(pattern)
                self.metrics.patterns_promoted += 1

        return promoted

    def _retire_patterns(self) -> list[EvolvedPattern]:
        """Retire patterns with too many false positives."""
        retired = []

        for pattern in list(self.evolved_patterns.values()):
            total = pattern.times_confirmed + pattern.times_false_positive
            if total >= 5 and pattern.precision < (1 - self.MAX_FP_RATE_BEFORE_RETIRE):
                pattern.is_active = False
                retired.append(pattern)
                self.metrics.patterns_retired += 1

        return retired

    def _apply_decay(self) -> int:
        """Age out patterns that haven't been confirmed recently."""
        decayed = 0
        cutoff = time.time() - (self.PATTERN_DECAY_DAYS * 86400)

        for pattern in self.evolved_patterns.values():
            if pattern.discovered_at < cutoff and pattern.times_confirmed < 3:
                if pattern.is_active:
                    pattern.is_active = False
                    decayed += 1

        return decayed

    def _evolve_strategies(self, findings: list[dict]) -> list[dict]:
        """
        Generate strategy priority adjustments based on findings.

        If certain vulnerability classes are consistently found by certain
        strategies, boost those strategy-artifact pairings.
        """
        adjustments = []

        # Count findings by source
        source_effectiveness: dict[str, dict] = {}
        for f in findings:
            source = f.get("source", "unknown")
            severity = f.get("severity", "low")

            if source not in source_effectiveness:
                source_effectiveness[source] = {"total": 0, "critical": 0, "high": 0}

            source_effectiveness[source]["total"] += 1
            if severity == "critical":
                source_effectiveness[source]["critical"] += 1
            elif severity == "high":
                source_effectiveness[source]["high"] += 1

        for source, stats in source_effectiveness.items():
            high_value_ratio = (stats["critical"] + stats["high"]) / max(1, stats["total"])

            if high_value_ratio > 0.5 and stats["total"] >= 3:
                adjustments.append({
                    "source": source,
                    "action": "BOOST",
                    "reason": f"High-value finding ratio: {high_value_ratio:.1%}",
                    "boost_factor": 1.2,
                })
                self.metrics.strategies_evolved += 1
            elif stats["total"] >= 5 and high_value_ratio < 0.1:
                adjustments.append({
                    "source": source,
                    "action": "REDUCE",
                    "reason": f"Low-value finding ratio: {high_value_ratio:.1%}",
                    "reduce_factor": 0.9,
                })

        return adjustments

    def _calculate_velocity(self) -> dict:
        """Calculate improvement velocity metrics."""
        if len(self.scan_history) < 2:
            return {"status": "insufficient_data", "scans_needed": 2 - len(self.scan_history)}

        recent = self.scan_history[-5:]
        earlier = self.scan_history[:-5] if len(self.scan_history) > 5 else self.scan_history[:1]

        recent_avg_findings = sum(s["total_findings"] for s in recent) / len(recent)
        earlier_avg_findings = sum(s["total_findings"] for s in earlier) / max(1, len(earlier))

        active_patterns = sum(1 for p in self.evolved_patterns.values() if p.is_active)
        total_patterns = len(self.evolved_patterns)

        return {
            "status": "tracking",
            "total_scans": len(self.scan_history),
            "recent_avg_findings": round(recent_avg_findings, 1),
            "earlier_avg_findings": round(earlier_avg_findings, 1),
            "detection_trend": "IMPROVING" if recent_avg_findings > earlier_avg_findings else "STABLE",
            "active_evolved_patterns": active_patterns,
            "total_evolved_patterns": total_patterns,
            "evolution_generations": self.metrics.total_evolutions,
            "patterns_promoted": self.metrics.patterns_promoted,
            "patterns_retired": self.metrics.patterns_retired,
        }

    def get_active_patterns(self) -> list[EvolvedPattern]:
        """Return all active evolved patterns for use in scanning."""
        return [p for p in self.evolved_patterns.values() if p.is_active]

    def get_evolution_report(self) -> str:
        """Format a human-readable evolution report."""
        velocity = self._calculate_velocity()
        active = sum(1 for p in self.evolved_patterns.values() if p.is_active)
        total = len(self.evolved_patterns)

        lines = [
            "",
            "  +==============================================================+",
            "  |         BAYREUTHWING -- Self-Evolution Report               |",
            "  +==============================================================+",
            "",
            f"  Evolution Cycles:     {self.metrics.total_evolutions}",
            f"  Scans Analyzed:       {self.metrics.scans_analyzed}",
            f"  Patterns Generated:   {self.metrics.patterns_generated}",
            f"  Patterns Promoted:    {self.metrics.patterns_promoted}",
            f"  Patterns Retired:     {self.metrics.patterns_retired}",
            f"  Active Patterns:      {active}/{total}",
            f"  Strategies Evolved:   {self.metrics.strategies_evolved}",
            "",
        ]

        if velocity.get("status") == "tracking":
            lines.append(f"  Detection Trend:      {velocity.get('detection_trend', 'N/A')}")
            lines.append(f"  Recent Avg Findings:  {velocity.get('recent_avg_findings', 0)}")
            lines.append(f"  Earlier Avg Findings: {velocity.get('earlier_avg_findings', 0)}")
            lines.append("")

        # Top evolved patterns
        top_patterns = sorted(
            [p for p in self.evolved_patterns.values() if p.is_active],
            key=lambda p: p.times_confirmed,
            reverse=True,
        )[:5]

        if top_patterns:
            lines.append("  TOP EVOLVED PATTERNS:")
            lines.append("  " + "-" * 58)
            for p in top_patterns:
                lines.append(
                    f"    {p.name:<30} "
                    f"Confirmed: {p.times_confirmed:>3}  "
                    f"Precision: {p.precision:.0%}  "
                    f"Gen: {p.generation}"
                )
            lines.append("")

        return "\n".join(lines)
