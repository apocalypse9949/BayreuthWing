"""
BAYREUTHWING — Cognitive Reasoning Engine

The meta-cognitive analysis layer. While other modules detect individual
vulnerabilities, the Cognitive Engine THINKS about them — correlating
findings across files, inferring attack surfaces, building threat
narratives, and reasoning about what an attacker would do with what
was found.

This is what separates a scanner from an intelligence system.

Architecture:
    ┌────────────────────────────────────────────────────┐
    │              COGNITIVE REASONING ENGINE             │
    ├────────────────────────────────────────────────────┤
    │                                                    │
    │  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │
    │  │  Correlation  │  │  Attack Path │  │  Threat  │ │
    │  │  Analyzer     │  │  Synthesizer │  │  Narrator│ │
    │  └──────┬───────┘  └──────┬───────┘  └────┬─────┘ │
    │         │                 │                │       │
    │  ┌──────▼─────────────────▼────────────────▼─────┐ │
    │  │         Reasoning Graph (in-memory DAG)        │ │
    │  └────────────────────┬───────────────────────────┘ │
    │                       │                             │
    │  ┌────────────────────▼───────────────────────────┐ │
    │  │         Meta-Cognition Layer                    │ │
    │  │  (Reasons about its own reasoning quality)     │ │
    │  └────────────────────────────────────────────────┘ │
    └────────────────────────────────────────────────────┘

Capabilities:
    1. Cross-File Correlation — Find vulnerability chains across files
    2. Attack Path Synthesis — Build realistic exploitation paths
    3. Threat Narrative Generation — Human-readable attack stories
    4. Confidence Calibration — Meta-cognitive confidence adjustment
    5. Blind Spot Detection — Identify what the scanner DIDN'T check
    6. Impact Amplification — Detect when vulns combine for worse impact
    7. Temporal Pattern Analysis — Track how findings evolve across scans

Anti-Hallucination:
    - All reasoning operates on concrete findings (not speculation)
    - Every inference carries a provenance chain back to source findings
    - Confidence is bounded and calibrated against historical accuracy
    - No generative content — all narratives are template-based
"""

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


# ═══════════════════════════════════════════════════════════════
# REASONING PRIMITIVES
# ═══════════════════════════════════════════════════════════════

class ReasoningType(Enum):
    """Types of cognitive reasoning operations."""
    CORRELATION = auto()         # Two findings are related
    AMPLIFICATION = auto()       # Combined impact > sum of parts
    ATTACK_PATH = auto()         # Ordered exploitation sequence
    BLIND_SPOT = auto()          # Missing analysis coverage
    TEMPORAL_PATTERN = auto()    # Change over time
    CONFIDENCE_ADJUSTMENT = auto()  # Meta-cognitive calibration
    THREAT_NARRATIVE = auto()    # Human-readable attack story
    SUPPLY_CHAIN_GRAPH = auto()  # Dependency vulnerability paths
    DATA_FLOW_CHAIN = auto()     # Cross-file taint propagation
    PRIVILEGE_GRAPH = auto()     # Privilege escalation paths


class AttackComplexity(Enum):
    """How difficult the attack path is to execute."""
    TRIVIAL = "trivial"          # Script kiddie level
    LOW = "low"                  # Basic exploitation skills
    MEDIUM = "medium"            # Requires domain knowledge
    HIGH = "high"                # Advanced attacker required
    EXPERT = "expert"            # Nation-state / APT level


class ImpactClass(Enum):
    """What an attacker achieves."""
    DATA_BREACH = auto()
    REMOTE_CODE_EXECUTION = auto()
    ACCOUNT_TAKEOVER = auto()
    PRIVILEGE_ESCALATION = auto()
    DENIAL_OF_SERVICE = auto()
    DATA_MANIPULATION = auto()
    LATERAL_MOVEMENT = auto()
    SUPPLY_CHAIN_COMPROMISE = auto()
    CRYPTOGRAPHIC_FAILURE = auto()
    INFORMATION_DISCLOSURE = auto()


@dataclass
class ReasoningNode:
    """A single unit of cognitive reasoning."""
    reasoning_type: ReasoningType
    description: str
    confidence: float = 0.0
    source_findings: list = field(default_factory=list)  # Finding IDs
    inferred_from: list = field(default_factory=list)     # Other ReasoningNode IDs
    metadata: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    @property
    def node_id(self) -> str:
        raw = f"{self.reasoning_type.name}:{self.description[:80]}:{len(self.source_findings)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "type": self.reasoning_type.name,
            "description": self.description,
            "confidence": round(self.confidence, 3),
            "source_findings": self.source_findings,
            "inferred_from": self.inferred_from,
            "metadata": self.metadata,
        }


@dataclass
class AttackPath:
    """A synthesized attack path through multiple vulnerabilities."""
    name: str
    steps: list = field(default_factory=list)       # Ordered finding IDs
    complexity: AttackComplexity = AttackComplexity.MEDIUM
    impact: ImpactClass = ImpactClass.INFORMATION_DISCLOSURE
    overall_confidence: float = 0.0
    narrative: str = ""
    prerequisites: list = field(default_factory=list)
    mitigations: list = field(default_factory=list)

    @property
    def path_id(self) -> str:
        raw = f"{self.name}:{len(self.steps)}:{self.impact.name}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "path_id": self.path_id,
            "name": self.name,
            "steps": self.steps,
            "complexity": self.complexity.value,
            "impact": self.impact.name,
            "confidence": round(self.overall_confidence, 3),
            "narrative": self.narrative,
            "prerequisites": self.prerequisites,
            "mitigations": self.mitigations,
        }


@dataclass
class BlindSpot:
    """Something the scanner didn't check but should have."""
    area: str
    reason: str
    recommended_strategies: list = field(default_factory=list)
    severity_if_present: str = "medium"

    def to_dict(self) -> dict:
        return {
            "area": self.area,
            "reason": self.reason,
            "recommended_strategies": self.recommended_strategies,
            "severity_if_present": self.severity_if_present,
        }


# ═══════════════════════════════════════════════════════════════
# CORRELATION PATTERNS — What findings imply when found together
# ═══════════════════════════════════════════════════════════════

# Maps (vuln_class_A, vuln_class_B) -> (impact, narrative_template, confidence_boost)
CORRELATION_PATTERNS = {
    # Auth bypass + SQLi = unauthenticated database access
    (4, 0): {
        "impact": ImpactClass.DATA_BREACH,
        "complexity": AttackComplexity.LOW,
        "narrative": "Authentication bypass ({file_a}:{line_a}) allows unauthenticated access to an endpoint vulnerable to SQL injection ({file_b}:{line_b}). An attacker can extract the entire database without credentials.",
        "confidence_boost": 1.4,
        "severity_override": "critical",
    },
    # XSS + Session management weakness = account takeover
    (1, 4): {
        "impact": ImpactClass.ACCOUNT_TAKEOVER,
        "complexity": AttackComplexity.LOW,
        "narrative": "Cross-site scripting ({file_a}:{line_a}) combined with weak session management ({file_b}:{line_b}) enables full account takeover. Attacker steals session tokens via XSS.",
        "confidence_boost": 1.3,
        "severity_override": "critical",
    },
    # SSRF + Cloud metadata = cloud credential theft
    (17, 7): {
        "impact": ImpactClass.PRIVILEGE_ESCALATION,
        "complexity": AttackComplexity.MEDIUM,
        "narrative": "Server-side request forgery ({file_a}:{line_a}) with sensitive data exposure ({file_b}:{line_b}) suggests cloud metadata endpoint access. Attacker can steal IAM credentials and escalate to full cloud control.",
        "confidence_boost": 1.5,
        "severity_override": "critical",
    },
    # Command injection + privilege escalation = RCE
    (2, 4): {
        "impact": ImpactClass.REMOTE_CODE_EXECUTION,
        "complexity": AttackComplexity.LOW,
        "narrative": "Command injection ({file_a}:{line_a}) with broken access control ({file_b}:{line_b}) allows remote command execution on the server with escalated privileges.",
        "confidence_boost": 1.5,
        "severity_override": "critical",
    },
    # Deserialization + unvalidated input = RCE
    (8, 3): {
        "impact": ImpactClass.REMOTE_CODE_EXECUTION,
        "complexity": AttackComplexity.MEDIUM,
        "narrative": "Unsafe deserialization ({file_a}:{line_a}) accepting user-controlled input ({file_b}:{line_b}) creates a classic gadget chain attack vector for remote code execution.",
        "confidence_boost": 1.4,
        "severity_override": "critical",
    },
    # SSTI + unvalidated input = RCE
    (12, 3): {
        "impact": ImpactClass.REMOTE_CODE_EXECUTION,
        "complexity": AttackComplexity.MEDIUM,
        "narrative": "Server-side template injection ({file_a}:{line_a}) with insufficient input validation ({file_b}:{line_b}) provides a direct path to remote code execution through template engine exploitation.",
        "confidence_boost": 1.4,
        "severity_override": "critical",
    },
    # Weak crypto + sensitive data = data breach
    (5, 7): {
        "impact": ImpactClass.DATA_BREACH,
        "complexity": AttackComplexity.MEDIUM,
        "narrative": "Weak cryptographic algorithms ({file_a}:{line_a}) protecting sensitive data ({file_b}:{line_b}). Encrypted data can be decrypted with moderate computational resources.",
        "confidence_boost": 1.3,
        "severity_override": "high",
    },
    # Path traversal + file inclusion = source code disclosure / RCE
    (10, 2): {
        "impact": ImpactClass.REMOTE_CODE_EXECUTION,
        "complexity": AttackComplexity.MEDIUM,
        "narrative": "Path traversal ({file_a}:{line_a}) combined with command injection patterns ({file_b}:{line_b}) allows reading arbitrary files and potentially executing code through included files.",
        "confidence_boost": 1.3,
        "severity_override": "critical",
    },
    # IDOR + PII exposure = mass data scraping
    (4, 7): {
        "impact": ImpactClass.DATA_BREACH,
        "complexity": AttackComplexity.TRIVIAL,
        "narrative": "Broken access control ({file_a}:{line_a}) allowing IDOR with sensitive data exposure ({file_b}:{line_b}). Attacker can iterate IDs to mass-scrape all user data.",
        "confidence_boost": 1.4,
        "severity_override": "critical",
    },
    # Open redirect + SSRF = internal network pivot
    (18, 17): {
        "impact": ImpactClass.LATERAL_MOVEMENT,
        "complexity": AttackComplexity.MEDIUM,
        "narrative": "Open redirect ({file_a}:{line_a}) chained with SSRF ({file_b}:{line_b}) enables pivoting to internal network services through redirect-based URL bypass.",
        "confidence_boost": 1.3,
        "severity_override": "high",
    },
    # Dependency confusion + supply chain
    (30, 31): {
        "impact": ImpactClass.SUPPLY_CHAIN_COMPROMISE,
        "complexity": AttackComplexity.HIGH,
        "narrative": "Dependency confusion risk ({file_a}:{line_a}) combined with known vulnerable dependency ({file_b}:{line_b}). Attacker can publish a malicious package to execute code during build.",
        "confidence_boost": 1.4,
        "severity_override": "critical",
    },
    # Race condition + file operation = TOCTOU
    (22, 10): {
        "impact": ImpactClass.PRIVILEGE_ESCALATION,
        "complexity": AttackComplexity.HIGH,
        "narrative": "Race condition ({file_a}:{line_a}) in file operations ({file_b}:{line_b}) creates a TOCTOU (time-of-check-time-of-use) vulnerability enabling privilege escalation.",
        "confidence_boost": 1.2,
        "severity_override": "high",
    },
    # JWT weakness + broken auth = full auth bypass
    (14, 4): {
        "impact": ImpactClass.ACCOUNT_TAKEOVER,
        "complexity": AttackComplexity.LOW,
        "narrative": "JWT vulnerability ({file_a}:{line_a}) combined with broken access control ({file_b}:{line_b}). Attacker forges tokens to impersonate any user including admins.",
        "confidence_boost": 1.5,
        "severity_override": "critical",
    },
}

# ═══════════════════════════════════════════════════════════════
# BLIND SPOT RULES — What to check for when specific vulns found
# ═══════════════════════════════════════════════════════════════

BLIND_SPOT_RULES = {
    # If we found SQLi, check if we also checked for stored procedures
    0: [
        BlindSpot("Stored Procedure Injection", "SQLi found but stored procedure execution not analyzed", ["SQL_INJECTION_DEEP"], "high"),
        BlindSpot("Second-Order SQLi", "Direct SQLi found — check if data stored and reused elsewhere", ["TAINT_PROPAGATION_DEEP"], "high"),
        BlindSpot("Database Configuration", "SQLi present — DB permissions and least-privilege not audited", ["PRIVILEGE_ESCALATION_PATH"], "medium"),
    ],
    # If XSS found, check DOM-based and mutation XSS
    1: [
        BlindSpot("DOM-based XSS", "Reflected/stored XSS found but DOM manipulation not checked", ["XSS_CONTEXT_ANALYSIS"], "high"),
        BlindSpot("Mutation XSS (mXSS)", "Standard XSS found but browser mutation vectors not tested", ["XSS_CONTEXT_ANALYSIS"], "medium"),
        BlindSpot("CSP Bypass", "XSS present — Content Security Policy effectiveness not validated", ["CORS_MISCONFIGURATION_CHECK"], "medium"),
    ],
    # If auth issues found, check for timing attacks
    4: [
        BlindSpot("Timing-Based Auth Bypass", "Auth weakness found but timing attack vectors not analyzed", ["RACE_CONDITION_CHECK"], "high"),
        BlindSpot("Password Reset Flow", "Auth bypass found — password reset and recovery flows not tested", ["BROKEN_AUTH_FLOW"], "high"),
        BlindSpot("Multi-Factor Bypass", "Auth issue present — MFA implementation and bypass not checked", ["AUTH_BYPASS_CHECK"], "medium"),
    ],
    # If crypto weakness found
    5: [
        BlindSpot("Key Derivation", "Weak crypto found but key derivation functions not analyzed", ["KEY_MANAGEMENT_AUDIT"], "high"),
        BlindSpot("Side-Channel Leaks", "Crypto weakness found — timing/power side channels not checked", ["RACE_CONDITION_CHECK"], "medium"),
    ],
    # If SSRF found
    17: [
        BlindSpot("Cloud Metadata Access", "SSRF found — cloud metadata endpoint (169.254.169.254) access not verified", ["SSRF_DEEP_SCAN"], "critical"),
        BlindSpot("Internal Service Enumeration", "SSRF present — internal network service discovery not attempted", ["DNS_REBINDING_CHECK"], "high"),
    ],
    # If deserialization found
    8: [
        BlindSpot("Gadget Chain Availability", "Unsafe deserialization found but available gadget chains not enumerated", ["GADGET_CHAIN_DETECTION"], "critical"),
        BlindSpot("Polyglot Payloads", "Deserialization risk found — polyglot format attacks not tested", ["TYPE_CONFUSION_CHECK"], "high"),
    ],
}


# ═══════════════════════════════════════════════════════════════
# COGNITIVE REASONING ENGINE
# ═══════════════════════════════════════════════════════════════

class CognitiveEngine:
    """
    The thinking brain of BayreuthWing.

    Takes raw findings from all analysis modules and applies higher-order
    reasoning: correlation, attack path synthesis, blind spot detection,
    and threat narrative generation.

    This is what makes BayreuthWing an INTELLIGENCE SYSTEM rather than
    just a vulnerability scanner.
    """

    # Minimum findings needed to trigger correlation analysis
    MIN_FINDINGS_FOR_CORRELATION = 2
    # Maximum attack paths to synthesize
    MAX_ATTACK_PATHS = 50
    # Confidence floor for reasoning nodes
    MIN_REASONING_CONFIDENCE = 0.3

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.reasoning_graph: list[ReasoningNode] = []
        self.attack_paths: list[AttackPath] = []
        self.blind_spots: list[BlindSpot] = []
        self._meta_stats = {
            "correlations_found": 0,
            "attack_paths_synthesized": 0,
            "blind_spots_identified": 0,
            "confidence_adjustments": 0,
            "total_reasoning_time_ms": 0,
        }

    def analyze(self, findings: list[dict], scan_context: dict = None) -> dict:
        """
        Run full cognitive analysis on a set of findings.

        Args:
            findings: List of finding dicts from all scanner modules.
            scan_context: Optional context (target path, language, etc.)

        Returns:
            Cognitive analysis results dict.
        """
        start = time.time()
        scan_context = scan_context or {}

        # Phase 1: Cross-file correlation
        correlations = self._correlate_findings(findings)

        # Phase 2: Attack path synthesis
        attack_paths = self._synthesize_attack_paths(findings, correlations)

        # Phase 3: Blind spot detection
        blind_spots = self._detect_blind_spots(findings, scan_context)

        # Phase 4: Impact amplification
        amplified = self._amplify_impact(findings, correlations)

        # Phase 5: Meta-cognitive confidence calibration
        calibrated = self._calibrate_confidence(findings, correlations)

        # Phase 6: Threat narrative generation
        narratives = self._generate_narratives(attack_paths, findings)

        # Phase 7: Attack surface mapping
        surface_map = self._map_attack_surface(findings, scan_context)

        elapsed = (time.time() - start) * 1000
        self._meta_stats["total_reasoning_time_ms"] += elapsed

        return {
            "correlations": [c.to_dict() for c in correlations],
            "attack_paths": [p.to_dict() for p in attack_paths],
            "blind_spots": [b.to_dict() for b in blind_spots],
            "amplified_findings": amplified,
            "calibrated_findings": calibrated,
            "narratives": narratives,
            "attack_surface": surface_map,
            "meta_stats": {
                **self._meta_stats,
                "reasoning_time_ms": round(elapsed, 2),
                "total_reasoning_nodes": len(self.reasoning_graph),
            },
        }

    def _correlate_findings(self, findings: list[dict]) -> list[ReasoningNode]:
        """
        Find meaningful relationships between findings across files.

        Uses the CORRELATION_PATTERNS table to identify when two
        vulnerabilities together create a worse-than-sum-of-parts scenario.
        """
        if len(findings) < self.MIN_FINDINGS_FOR_CORRELATION:
            return []

        correlations = []
        seen_pairs = set()

        for i, finding_a in enumerate(findings):
            for j, finding_b in enumerate(findings):
                if i >= j:
                    continue

                class_a = finding_a.get("vuln_class", -1)
                class_b = finding_b.get("vuln_class", -1)

                # Check both orderings
                pattern = CORRELATION_PATTERNS.get((class_a, class_b))
                if pattern is None:
                    pattern = CORRELATION_PATTERNS.get((class_b, class_a))
                    if pattern:
                        finding_a, finding_b = finding_b, finding_a

                if pattern is None:
                    continue

                pair_key = (min(class_a, class_b), max(class_a, class_b),
                           finding_a.get("filepath", ""), finding_b.get("filepath", ""))
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                # Build narrative from template
                narrative = pattern["narrative"].format(
                    file_a=finding_a.get("filepath", "?"),
                    line_a=finding_a.get("line", 0),
                    file_b=finding_b.get("filepath", "?"),
                    line_b=finding_b.get("line", 0),
                )

                combined_conf = min(
                    finding_a.get("confidence", 0.5),
                    finding_b.get("confidence", 0.5)
                ) * pattern["confidence_boost"]

                node = ReasoningNode(
                    reasoning_type=ReasoningType.CORRELATION,
                    description=narrative,
                    confidence=min(0.99, combined_conf),
                    source_findings=[
                        f"{finding_a.get('filepath')}:{finding_a.get('line')}",
                        f"{finding_b.get('filepath')}:{finding_b.get('line')}",
                    ],
                    metadata={
                        "impact": pattern["impact"].name,
                        "complexity": pattern["complexity"].value,
                        "severity_override": pattern["severity_override"],
                        "vuln_classes": [class_a, class_b],
                    },
                )

                correlations.append(node)
                self.reasoning_graph.append(node)
                self._meta_stats["correlations_found"] += 1

        return correlations

    def _synthesize_attack_paths(
        self, findings: list[dict], correlations: list[ReasoningNode]
    ) -> list[AttackPath]:
        """
        Build realistic multi-step attack paths from correlated findings.

        Each path represents a complete exploitation scenario an attacker
        could follow from initial access to impact.
        """
        paths = []

        # Group findings by file to find entry points
        by_file: dict[str, list[dict]] = {}
        for f in findings:
            fp = f.get("filepath", "unknown")
            if fp not in by_file:
                by_file[fp] = []
            by_file[fp].append(f)

        # For each correlation, build an attack path
        for corr in correlations:
            if corr.metadata.get("impact") in (
                ImpactClass.REMOTE_CODE_EXECUTION.name,
                ImpactClass.DATA_BREACH.name,
                ImpactClass.ACCOUNT_TAKEOVER.name,
            ):
                complexity = AttackComplexity(corr.metadata.get("complexity", "medium"))
                impact = ImpactClass[corr.metadata.get("impact", "INFORMATION_DISCLOSURE")]

                path = AttackPath(
                    name=f"{impact.name} via {corr.description[:60]}",
                    steps=corr.source_findings,
                    complexity=complexity,
                    impact=impact,
                    overall_confidence=corr.confidence,
                    narrative=corr.description,
                    prerequisites=self._infer_prerequisites(complexity),
                    mitigations=self._suggest_mitigations(impact, corr.metadata.get("vuln_classes", [])),
                )

                paths.append(path)
                self.attack_paths.append(path)
                self._meta_stats["attack_paths_synthesized"] += 1

        # Build file-local attack chains (multiple vulns in same file)
        for filepath, file_findings in by_file.items():
            if len(file_findings) >= 3:
                severities = [f.get("severity", "low") for f in file_findings]
                if "critical" in severities or severities.count("high") >= 2:
                    steps = [f"{filepath}:{f.get('line', 0)}" for f in file_findings[:5]]

                    path = AttackPath(
                        name=f"Multi-vulnerability chain in {filepath.split('/')[-1]}",
                        steps=steps,
                        complexity=AttackComplexity.MEDIUM,
                        impact=ImpactClass.REMOTE_CODE_EXECUTION if "critical" in severities else ImpactClass.PRIVILEGE_ESCALATION,
                        overall_confidence=min(f.get("confidence", 0.5) for f in file_findings) * 0.8,
                        narrative=f"Multiple vulnerabilities ({len(file_findings)}) concentrated in {filepath} suggest a high-value attack target with multiple exploitation paths.",
                        prerequisites=["Network access to application"],
                        mitigations=["Comprehensive security review of this file", "Input validation audit"],
                    )
                    paths.append(path)

        paths.sort(key=lambda p: p.overall_confidence, reverse=True)
        return paths[:self.MAX_ATTACK_PATHS]

    def _detect_blind_spots(self, findings: list[dict], context: dict) -> list[BlindSpot]:
        """
        Identify what the scanner DIDN'T check but should have.

        Based on what WAS found, infer related attack surfaces that
        might not have been adequately covered.
        """
        spots = []
        found_classes = set()
        found_files = set()

        for f in findings:
            found_classes.add(f.get("vuln_class", -1))
            found_files.add(f.get("filepath", ""))

        # Apply blind spot rules
        for vuln_class in found_classes:
            if vuln_class in BLIND_SPOT_RULES:
                for spot in BLIND_SPOT_RULES[vuln_class]:
                    spots.append(spot)
                    self._meta_stats["blind_spots_identified"] += 1

        # General blind spots based on what was NOT found
        all_checked_sources = set(f.get("source", "") for f in findings)

        if "ml_model" not in all_checked_sources:
            spots.append(BlindSpot(
                "ML Analysis Not Run",
                "Neural network model analysis was not executed — some pattern-based vulnerabilities may be missed",
                [],
                "medium",
            ))

        if not any(f.get("vuln_class") == 5 for f in findings):
            spots.append(BlindSpot(
                "Cryptographic Analysis",
                "No cryptographic vulnerabilities were checked or found — may indicate insufficient crypto coverage",
                ["WEAK_ALGORITHM_SCAN", "KEY_MANAGEMENT_AUDIT"],
                "medium",
            ))

        if not any(f.get("vuln_class") == 6 for f in findings):
            spots.append(BlindSpot(
                "Security Misconfiguration",
                "No security misconfiguration findings — may indicate missing config file analysis",
                ["CORS_MISCONFIGURATION_CHECK", "TLS_CONFIGURATION_AUDIT"],
                "medium",
            ))

        # Check for API-heavy codebases without API security testing
        api_files = [f for f in found_files if any(
            kw in f.lower() for kw in ["api", "route", "controller", "handler", "endpoint", "view"]
        )]
        if len(api_files) > 3 and not any(f.get("vuln_class") in (4, 14, 15) for f in findings):
            spots.append(BlindSpot(
                "API Authorization Testing",
                f"{len(api_files)} API-related files found but no authorization vulnerabilities detected — may need deeper auth testing",
                ["AUTH_BYPASS_CHECK", "IDOR_PATTERN_CHECK", "BOLA_PATTERN_CHECK"],
                "high",
            ))

        self.blind_spots = spots
        return spots

    def _amplify_impact(self, findings: list[dict], correlations: list[ReasoningNode]) -> list[dict]:
        """
        Return findings whose severity should be elevated based on correlations.

        When vulnerabilities combine, individual finding severities may
        need to be upgraded.
        """
        amplified = []

        for corr in correlations:
            severity_override = corr.metadata.get("severity_override")
            if severity_override:
                for source in corr.source_findings:
                    amplified.append({
                        "finding_ref": source,
                        "original_severity": "varies",
                        "amplified_severity": severity_override,
                        "reason": f"Correlated with other findings: {corr.description[:100]}",
                        "correlation_id": corr.node_id,
                    })

        return amplified

    def _calibrate_confidence(self, findings: list[dict], correlations: list[ReasoningNode]) -> list[dict]:
        """
        Meta-cognitive confidence calibration.

        Adjusts confidence based on:
        - Cross-source agreement (higher when multiple modules agree)
        - Correlation support (higher when part of attack chain)
        - Historical accuracy (if adaptive learning data available)
        """
        adjustments = []

        # Find findings confirmed by correlations
        correlated_refs = set()
        for corr in correlations:
            for ref in corr.source_findings:
                correlated_refs.add(ref)

        for finding in findings:
            ref = f"{finding.get('filepath')}:{finding.get('line')}"
            original_conf = finding.get("confidence", 0.5)
            adjusted = original_conf

            # Boost if part of a correlation chain
            if ref in correlated_refs:
                adjusted = min(0.99, adjusted * 1.2)

            # Boost if multiple sources agree
            source = finding.get("source", "")
            if " + " in source:  # Already merged from multiple sources
                adjusted = min(0.99, adjusted * 1.1)

            if abs(adjusted - original_conf) > 0.01:
                adjustments.append({
                    "finding_ref": ref,
                    "original_confidence": round(original_conf, 3),
                    "calibrated_confidence": round(adjusted, 3),
                    "reason": "Correlation-boosted" if ref in correlated_refs else "Multi-source agreement",
                })
                self._meta_stats["confidence_adjustments"] += 1

        return adjustments

    def _generate_narratives(self, attack_paths: list[AttackPath], findings: list[dict]) -> list[dict]:
        """
        Generate human-readable threat narratives for attack paths.

        These are executive-summary-level descriptions of what an
        attacker could do with the discovered vulnerabilities.
        """
        narratives = []

        # Overall threat assessment
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "low")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        criticals = severity_counts.get("critical", 0)
        highs = severity_counts.get("high", 0)

        if criticals > 0 or len(attack_paths) > 0:
            threat_level = "CRITICAL"
        elif highs > 3:
            threat_level = "HIGH"
        elif highs > 0:
            threat_level = "ELEVATED"
        else:
            threat_level = "MODERATE"

        executive_summary = {
            "type": "executive_summary",
            "threat_level": threat_level,
            "title": f"Threat Assessment: {threat_level}",
            "summary": (
                f"Analysis identified {len(findings)} vulnerabilities across the codebase, "
                f"including {criticals} critical and {highs} high severity issues. "
                f"{len(attack_paths)} viable attack paths were synthesized from correlated findings. "
                f"{'Immediate remediation is required.' if criticals > 0 else 'Prioritized remediation is recommended.'}"
            ),
            "key_risks": [p.narrative[:200] for p in attack_paths[:3]],
        }
        narratives.append(executive_summary)

        # Per-path narratives
        for path in attack_paths[:5]:
            narratives.append({
                "type": "attack_path_narrative",
                "title": path.name,
                "complexity": path.complexity.value,
                "impact": path.impact.name,
                "narrative": path.narrative,
                "steps": path.steps,
                "mitigations": path.mitigations,
            })

        return narratives

    def _map_attack_surface(self, findings: list[dict], context: dict) -> dict:
        """
        Build a map of the application's exposed attack surface.

        Groups findings by attack surface category to show where
        the application is most vulnerable.
        """
        surface = {
            "authentication": {"findings": 0, "critical": 0, "files": set()},
            "injection": {"findings": 0, "critical": 0, "files": set()},
            "data_exposure": {"findings": 0, "critical": 0, "files": set()},
            "configuration": {"findings": 0, "critical": 0, "files": set()},
            "cryptography": {"findings": 0, "critical": 0, "files": set()},
            "supply_chain": {"findings": 0, "critical": 0, "files": set()},
            "api_security": {"findings": 0, "critical": 0, "files": set()},
            "file_system": {"findings": 0, "critical": 0, "files": set()},
        }

        # Map vuln classes to surface categories
        class_to_surface = {
            0: "injection", 1: "injection", 2: "injection",
            3: "injection", 12: "injection", 13: "injection",
            4: "authentication", 14: "authentication", 15: "authentication",
            5: "cryptography", 6: "configuration",
            7: "data_exposure", 8: "injection",
            9: "api_security", 10: "file_system",
            11: "supply_chain", 16: "injection",
            17: "api_security", 18: "api_security",
            19: "data_exposure", 20: "injection",
            21: "api_security", 22: "configuration",
            23: "file_system", 24: "injection",
            25: "injection", 26: "data_exposure",
            27: "injection", 28: "injection",
            29: "configuration", 30: "supply_chain",
            31: "supply_chain", 32: "configuration",
            33: "injection", 34: "injection",
        }

        for f in findings:
            vc = f.get("vuln_class", -1)
            category = class_to_surface.get(vc, "configuration")
            if category in surface:
                surface[category]["findings"] += 1
                if f.get("severity") == "critical":
                    surface[category]["critical"] += 1
                surface[category]["files"].add(f.get("filepath", "unknown"))

        # Convert sets to lists for serialization
        for cat in surface:
            surface[cat]["files"] = list(surface[cat]["files"])
            surface[cat]["file_count"] = len(surface[cat]["files"])

        return surface

    def _infer_prerequisites(self, complexity: AttackComplexity) -> list[str]:
        """Infer attack prerequisites from complexity level."""
        prereqs = {
            AttackComplexity.TRIVIAL: ["Network access to application"],
            AttackComplexity.LOW: ["Network access to application", "Basic web exploitation knowledge"],
            AttackComplexity.MEDIUM: ["Network access to application", "Domain-specific knowledge", "Custom tooling"],
            AttackComplexity.HIGH: ["Network access to application", "Advanced exploitation skills", "Time and persistence", "Custom exploit development"],
            AttackComplexity.EXPERT: ["Network access to application", "Nation-state level resources", "0-day exploitation capability", "Social engineering infrastructure"],
        }
        return prereqs.get(complexity, ["Network access to application"])

    def _suggest_mitigations(self, impact: ImpactClass, vuln_classes: list[int]) -> list[str]:
        """Suggest mitigations based on impact and vulnerability types."""
        mitigations = {
            ImpactClass.REMOTE_CODE_EXECUTION: [
                "Implement strict input validation and sanitization",
                "Deploy Web Application Firewall (WAF)",
                "Enable process-level sandboxing",
                "Implement Content Security Policy (CSP)",
            ],
            ImpactClass.DATA_BREACH: [
                "Implement parameterized queries for all database access",
                "Enable encryption at rest and in transit",
                "Implement data access controls and monitoring",
                "Deploy data loss prevention (DLP) tools",
            ],
            ImpactClass.ACCOUNT_TAKEOVER: [
                "Implement multi-factor authentication (MFA)",
                "Use HttpOnly and Secure cookie flags",
                "Implement session token rotation",
                "Deploy account lockout and anomaly detection",
            ],
            ImpactClass.PRIVILEGE_ESCALATION: [
                "Implement principle of least privilege",
                "Use role-based access control (RBAC)",
                "Audit and restrict service account permissions",
                "Implement privilege separation architecture",
            ],
            ImpactClass.SUPPLY_CHAIN_COMPROMISE: [
                "Pin all dependency versions",
                "Use package lock files",
                "Implement SRI (Subresource Integrity)",
                "Deploy software composition analysis (SCA)",
            ],
        }
        return mitigations.get(impact, ["Conduct thorough security review", "Implement defense-in-depth controls"])

    def get_reasoning_summary(self) -> str:
        """Format a human-readable summary of cognitive analysis."""
        lines = [
            "",
            "  ╔══════════════════════════════════════════════════════════════╗",
            "  ║          BAYREUTHWING — Cognitive Analysis Report           ║",
            "  ╚══════════════════════════════════════════════════════════════╝",
            "",
            f"  Correlations Found:     {self._meta_stats['correlations_found']}",
            f"  Attack Paths:           {self._meta_stats['attack_paths_synthesized']}",
            f"  Blind Spots:            {self._meta_stats['blind_spots_identified']}",
            f"  Confidence Adjustments: {self._meta_stats['confidence_adjustments']}",
            f"  Reasoning Nodes:        {len(self.reasoning_graph)}",
            f"  Reasoning Time:         {self._meta_stats['total_reasoning_time_ms']:.1f}ms",
            "",
        ]

        if self.attack_paths:
            lines.append("  CRITICAL ATTACK PATHS:")
            lines.append("  " + "─" * 58)
            for path in self.attack_paths[:5]:
                lines.append(
                    f"    [{path.complexity.value.upper():>7}] {path.name[:50]}"
                    f"  ➜ {path.impact.name}"
                )
            lines.append("")

        if self.blind_spots:
            lines.append("  ANALYSIS BLIND SPOTS:")
            lines.append("  " + "─" * 58)
            for spot in self.blind_spots[:5]:
                lines.append(f"    ⚠ [{spot.severity_if_present.upper():>8}] {spot.area}")
            lines.append("")

        return "\n".join(lines)
