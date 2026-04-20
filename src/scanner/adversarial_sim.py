"""
BAYREUTHWING — Adversarial Simulation Engine

Thinks like an attacker. This module simulates attacker behavior to
identify exploitation paths that traditional scanners miss. It models:

    1. Attacker Personas — Different threat actor profiles (script kiddie → APT)
    2. Kill Chain Simulation — MITRE ATT&CK-aligned attack progression
    3. Chained Exploitation — Multi-step attacks using multiple vulnerabilities
    4. Privilege Escalation Graphs — Map all paths to higher privileges
    5. Lateral Movement Modeling — How an attacker moves through the system
    6. Data Exfiltration Paths — Routes for stealing sensitive data
    7. Persistence Mechanisms — How an attacker maintains access

Architecture:
    ┌────────────────────────────────────────────────────────┐
    │              ADVERSARIAL SIMULATION ENGINE              │
    ├────────────────────────────────────────────────────────┤
    │                                                        │
    │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐│
    │  │ Persona  │  │Kill Chain│  │ Privesc  │  │ Lateral││
    │  │ Modeler  │  │Simulator │  │ Grapher  │  │Movement││
    │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └───┬────┘│
    │       └─────────────┼─────────────┼─────────────┘     │
    │              ┌──────▼─────────────▼──────┐            │
    │              │   Exploitation Planner     │            │
    │              └────────────────────────────┘            │
    └────────────────────────────────────────────────────────┘

Anti-Hallucination:
    - All attack steps map to concrete vulnerability findings
    - Persona behaviors are template-defined, not generated
    - Kill chain phases are MITRE ATT&CK bounded
    - Exploitation feasibility scored by real vulnerability data
"""

import time
from dataclasses import dataclass, field
from enum import Enum, auto


# ═══════════════════════════════════════════════════════════════
# THREAT ACTOR PROFILES
# ═══════════════════════════════════════════════════════════════

class ThreatActorLevel(Enum):
    """Attacker capability levels."""
    SCRIPT_KIDDIE = 1     # Uses public tools, no customization
    OPPORTUNIST = 2       # Moderate skill, targets easy wins
    PROFESSIONAL = 3      # Skilled attacker, custom tools
    ORGANIZED_CRIME = 4   # Team-based, financially motivated
    APT = 5               # Nation-state, unlimited resources


@dataclass
class ThreatActor:
    """A modeled threat actor with capabilities and motivations."""
    level: ThreatActorLevel
    name: str
    motivation: str
    capabilities: list = field(default_factory=list)
    typical_targets: list = field(default_factory=list)
    max_exploit_complexity: str = "medium"
    persistence: bool = False   # Will establish persistence?
    stealth: bool = False       # Will try to avoid detection?
    time_budget_hours: int = 1  # How long they'll spend

    def to_dict(self) -> dict:
        return {
            "level": self.level.value,
            "level_name": self.level.name,
            "name": self.name,
            "motivation": self.motivation,
            "capabilities": self.capabilities,
            "max_complexity": self.max_exploit_complexity,
            "persistence": self.persistence,
            "stealth": self.stealth,
            "time_budget_hours": self.time_budget_hours,
        }


# Predefined threat actor profiles
THREAT_ACTORS = {
    ThreatActorLevel.SCRIPT_KIDDIE: ThreatActor(
        level=ThreatActorLevel.SCRIPT_KIDDIE,
        name="Script Kiddie",
        motivation="Notoriety, vandalism",
        capabilities=["Public exploits", "Automated scanning tools", "Default credentials"],
        typical_targets=["Known CVEs", "Default configs", "Exposed admin panels"],
        max_exploit_complexity="low",
        persistence=False,
        stealth=False,
        time_budget_hours=1,
    ),
    ThreatActorLevel.OPPORTUNIST: ThreatActor(
        level=ThreatActorLevel.OPPORTUNIST,
        name="Opportunistic Attacker",
        motivation="Financial gain, data theft",
        capabilities=["Custom scripts", "Social engineering", "Credential stuffing", "SQLi/XSS exploitation"],
        typical_targets=["Databases", "User credentials", "Payment data", "PII"],
        max_exploit_complexity="medium",
        persistence=False,
        stealth=False,
        time_budget_hours=8,
    ),
    ThreatActorLevel.PROFESSIONAL: ThreatActor(
        level=ThreatActorLevel.PROFESSIONAL,
        name="Professional Hacker",
        motivation="Targeted attack, bug bounty, espionage",
        capabilities=["Custom exploits", "Reverse engineering", "Binary analysis", "Chain exploitation", "WAF bypass"],
        typical_targets=["Critical infrastructure", "Source code", "Internal networks", "Cloud credentials"],
        max_exploit_complexity="high",
        persistence=True,
        stealth=True,
        time_budget_hours=40,
    ),
    ThreatActorLevel.ORGANIZED_CRIME: ThreatActor(
        level=ThreatActorLevel.ORGANIZED_CRIME,
        name="Organized Crime Group",
        motivation="Ransomware, fraud, data extortion",
        capabilities=["Team-based attacks", "Custom malware", "Ransomware deployment", "Supply chain attacks", "Insider recruitment"],
        typical_targets=["Financial data", "Encryption keys", "Backup systems", "Payment processors"],
        max_exploit_complexity="high",
        persistence=True,
        stealth=True,
        time_budget_hours=200,
    ),
    ThreatActorLevel.APT: ThreatActor(
        level=ThreatActorLevel.APT,
        name="Advanced Persistent Threat (APT)",
        motivation="Strategic intelligence, sabotage, long-term access",
        capabilities=["Zero-day exploits", "Custom implants", "Hardware attacks", "Social engineering campaigns", "Supply chain compromise", "Satellite interception"],
        typical_targets=["State secrets", "Critical infrastructure", "Research data", "Military systems"],
        max_exploit_complexity="expert",
        persistence=True,
        stealth=True,
        time_budget_hours=8760,  # Year-long campaigns
    ),
}


# ═══════════════════════════════════════════════════════════════
# MITRE ATT&CK KILL CHAIN
# ═══════════════════════════════════════════════════════════════

class KillChainPhase(Enum):
    """MITRE ATT&CK inspired kill chain phases."""
    RECONNAISSANCE = auto()
    INITIAL_ACCESS = auto()
    EXECUTION = auto()
    PERSISTENCE = auto()
    PRIVILEGE_ESCALATION = auto()
    DEFENSE_EVASION = auto()
    CREDENTIAL_ACCESS = auto()
    DISCOVERY = auto()
    LATERAL_MOVEMENT = auto()
    COLLECTION = auto()
    EXFILTRATION = auto()
    IMPACT = auto()


# Map vulnerability classes to kill chain phases they enable
VULN_TO_KILLCHAIN = {
    # SQLi enables multiple phases
    0: [KillChainPhase.INITIAL_ACCESS, KillChainPhase.CREDENTIAL_ACCESS, KillChainPhase.COLLECTION],
    # XSS
    1: [KillChainPhase.INITIAL_ACCESS, KillChainPhase.CREDENTIAL_ACCESS],
    # Command Injection
    2: [KillChainPhase.EXECUTION, KillChainPhase.PRIVILEGE_ESCALATION],
    # Input Validation
    3: [KillChainPhase.INITIAL_ACCESS],
    # Broken Access Control
    4: [KillChainPhase.PRIVILEGE_ESCALATION, KillChainPhase.LATERAL_MOVEMENT],
    # Crypto Failures
    5: [KillChainPhase.CREDENTIAL_ACCESS, KillChainPhase.COLLECTION],
    # Security Misconfig
    6: [KillChainPhase.RECONNAISSANCE, KillChainPhase.INITIAL_ACCESS],
    # Sensitive Data Exposure
    7: [KillChainPhase.COLLECTION, KillChainPhase.EXFILTRATION],
    # Insecure Deserialization
    8: [KillChainPhase.EXECUTION, KillChainPhase.PERSISTENCE],
    # Logging/Monitoring
    9: [KillChainPhase.DEFENSE_EVASION],
    # Path Traversal
    10: [KillChainPhase.COLLECTION, KillChainPhase.DISCOVERY],
    # Supply Chain
    11: [KillChainPhase.INITIAL_ACCESS, KillChainPhase.PERSISTENCE],
    # SSTI
    12: [KillChainPhase.EXECUTION, KillChainPhase.PRIVILEGE_ESCALATION],
    # XXE
    13: [KillChainPhase.COLLECTION, KillChainPhase.INITIAL_ACCESS],
    # JWT
    14: [KillChainPhase.CREDENTIAL_ACCESS, KillChainPhase.PRIVILEGE_ESCALATION],
    # Mass Assignment
    15: [KillChainPhase.PRIVILEGE_ESCALATION],
    # IDOR
    16: [KillChainPhase.COLLECTION, KillChainPhase.LATERAL_MOVEMENT],
    # SSRF
    17: [KillChainPhase.DISCOVERY, KillChainPhase.LATERAL_MOVEMENT, KillChainPhase.CREDENTIAL_ACCESS],
    # Open Redirect
    18: [KillChainPhase.INITIAL_ACCESS],
    # Info Disclosure
    19: [KillChainPhase.RECONNAISSANCE, KillChainPhase.DISCOVERY],
    # CORS Misconfig
    20: [KillChainPhase.INITIAL_ACCESS, KillChainPhase.CREDENTIAL_ACCESS],
    # Prototype Pollution
    21: [KillChainPhase.EXECUTION],
    # Race Condition
    22: [KillChainPhase.PRIVILEGE_ESCALATION],
    # File Upload
    23: [KillChainPhase.EXECUTION, KillChainPhase.PERSISTENCE],
    # ReDoS
    24: [KillChainPhase.IMPACT],
    # Log Injection
    25: [KillChainPhase.DEFENSE_EVASION],
    # CRLF Injection
    26: [KillChainPhase.INITIAL_ACCESS],
    # Header Injection
    27: [KillChainPhase.INITIAL_ACCESS, KillChainPhase.DEFENSE_EVASION],
    # Business Logic
    28: [KillChainPhase.IMPACT, KillChainPhase.COLLECTION],
    # Integer Overflow
    29: [KillChainPhase.EXECUTION],
    # Dependency Confusion
    30: [KillChainPhase.INITIAL_ACCESS, KillChainPhase.PERSISTENCE],
    # Vulnerable Dependencies
    31: [KillChainPhase.INITIAL_ACCESS],
    # Insecure Config
    32: [KillChainPhase.RECONNAISSANCE, KillChainPhase.INITIAL_ACCESS],
    # LDAP Injection
    33: [KillChainPhase.CREDENTIAL_ACCESS, KillChainPhase.INITIAL_ACCESS],
    # XPath Injection
    34: [KillChainPhase.COLLECTION],
}


@dataclass
class KillChainStep:
    """A single step in a simulated attack."""
    phase: KillChainPhase
    technique: str
    finding_ref: str      # Reference to the finding that enables this
    vuln_class: int
    description: str
    success_probability: float = 0.5
    detection_probability: float = 0.5
    prerequisites: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "phase": self.phase.name,
            "technique": self.technique,
            "finding_ref": self.finding_ref,
            "vuln_class": self.vuln_class,
            "description": self.description,
            "success_probability": round(self.success_probability, 3),
            "detection_probability": round(self.detection_probability, 3),
        }


@dataclass
class AttackSimulation:
    """A complete simulated attack scenario."""
    name: str
    actor: ThreatActor
    kill_chain: list = field(default_factory=list)  # KillChainSteps
    overall_success_probability: float = 0.0
    overall_detection_probability: float = 0.0
    max_impact: str = "low"
    total_steps: int = 0
    phases_covered: int = 0
    narrative: str = ""
    countermeasures: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "actor": self.actor.to_dict(),
            "kill_chain": [s.to_dict() for s in self.kill_chain],
            "overall_success_probability": round(self.overall_success_probability, 3),
            "overall_detection_probability": round(self.overall_detection_probability, 3),
            "max_impact": self.max_impact,
            "total_steps": self.total_steps,
            "phases_covered": self.phases_covered,
            "narrative": self.narrative,
            "countermeasures": self.countermeasures,
        }


# ═══════════════════════════════════════════════════════════════
# ADVERSARIAL SIMULATION ENGINE
# ═══════════════════════════════════════════════════════════════

class AdversarialSimulator:
    """
    Simulates realistic attacker behavior against discovered vulnerabilities.

    For each threat actor profile, builds a complete attack simulation
    showing how they would chain vulnerabilities to achieve their goals.
    This helps defenders understand real-world risk beyond individual
    vulnerability severity.
    """

    # Complexity thresholds for what different actors can exploit
    COMPLEXITY_THRESHOLDS = {
        "trivial": ThreatActorLevel.SCRIPT_KIDDIE,
        "low": ThreatActorLevel.SCRIPT_KIDDIE,
        "medium": ThreatActorLevel.OPPORTUNIST,
        "high": ThreatActorLevel.PROFESSIONAL,
        "expert": ThreatActorLevel.APT,
    }

    # Map vulnerability severity to exploitation success probability
    SEVERITY_TO_SUCCESS = {
        "critical": 0.9,
        "high": 0.7,
        "medium": 0.4,
        "low": 0.2,
    }

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.simulations: list[AttackSimulation] = []

    def simulate(self, findings: list[dict], actor_levels: list[ThreatActorLevel] = None) -> dict:
        """
        Run adversarial simulation across specified threat actor levels.

        Args:
            findings: List of finding dicts from scanner.
            actor_levels: Which threat actors to simulate (None = all).

        Returns:
            Complete simulation results.
        """
        if actor_levels is None:
            actor_levels = list(ThreatActorLevel)

        start = time.time()
        results = {
            "simulations": [],
            "risk_matrix": {},
            "priority_targets": [],
            "maximum_achievable_impact": "none",
            "simulation_time_ms": 0,
        }

        if not findings:
            return results

        for level in actor_levels:
            actor = THREAT_ACTORS.get(level)
            if not actor:
                continue

            sim = self._simulate_actor(actor, findings)
            if sim.total_steps > 0:
                self.simulations.append(sim)
                results["simulations"].append(sim.to_dict())

        # Build risk matrix
        results["risk_matrix"] = self._build_risk_matrix(findings)

        # Identify priority targets
        results["priority_targets"] = self._identify_priority_targets(findings)

        # Maximum achievable impact
        if results["simulations"]:
            max_impact = max(results["simulations"], key=lambda s: s.get("overall_success_probability", 0))
            results["maximum_achievable_impact"] = max_impact.get("max_impact", "none")

        results["simulation_time_ms"] = round((time.time() - start) * 1000, 2)

        return results

    def _simulate_actor(self, actor: ThreatActor, findings: list[dict]) -> AttackSimulation:
        """
        Simulate a specific threat actor attacking with available vulnerabilities.
        """
        # Filter findings to what this actor can exploit
        exploitable = self._filter_exploitable(actor, findings)

        if not exploitable:
            return AttackSimulation(
                name=f"{actor.name} Simulation",
                actor=actor,
                narrative=f"{actor.name} cannot exploit any discovered vulnerabilities due to complexity constraints.",
            )

        # Build kill chain
        kill_chain = self._build_kill_chain(actor, exploitable)

        # Calculate overall probabilities
        if kill_chain:
            success_probs = [s.success_probability for s in kill_chain]
            # Chain probability (each step must succeed)
            chain_success = 1.0
            for p in success_probs:
                chain_success *= p

            # Detection probability (any step can trigger detection)
            detect_probs = [s.detection_probability for s in kill_chain]
            chain_undetected = 1.0
            for p in detect_probs:
                chain_undetected *= (1 - p)
            chain_detected = 1 - chain_undetected

            phases_covered = len(set(s.phase for s in kill_chain))

            # Determine max impact
            max_severity = "low"
            for f in exploitable:
                sev = f.get("severity", "low")
                if sev == "critical":
                    max_severity = "critical"
                    break
                elif sev == "high" and max_severity != "critical":
                    max_severity = "high"
                elif sev == "medium" and max_severity not in ("critical", "high"):
                    max_severity = "medium"

            narrative = self._generate_attack_narrative(actor, kill_chain, exploitable)
            countermeasures = self._suggest_countermeasures(kill_chain)

            return AttackSimulation(
                name=f"{actor.name} Attack Simulation",
                actor=actor,
                kill_chain=kill_chain,
                overall_success_probability=chain_success,
                overall_detection_probability=chain_detected,
                max_impact=max_severity,
                total_steps=len(kill_chain),
                phases_covered=phases_covered,
                narrative=narrative,
                countermeasures=countermeasures,
            )

        return AttackSimulation(name=f"{actor.name} Simulation", actor=actor)

    def _filter_exploitable(self, actor: ThreatActor, findings: list[dict]) -> list[dict]:
        """Filter findings to only those the actor can exploit."""
        complexity_order = {"trivial": 0, "low": 1, "medium": 2, "high": 3, "expert": 4}
        actor_max = complexity_order.get(actor.max_exploit_complexity, 2)

        exploitable = []
        for f in findings:
            # Determine exploit complexity from severity
            severity = f.get("severity", "low")
            if severity == "critical":
                needed = 1  # Easy to exploit (that's why it's critical)
            elif severity == "high":
                needed = 2
            elif severity == "medium":
                needed = 2
            else:
                needed = 1

            if needed <= actor_max:
                exploitable.append(f)

        return exploitable

    def _build_kill_chain(self, actor: ThreatActor, findings: list[dict]) -> list[KillChainStep]:
        """Build a kill chain from exploitable findings following ATT&CK phases."""
        steps = []
        covered_phases = set()

        # Sort findings by kill chain phase order
        phase_order = list(KillChainPhase)
        finding_phases = []

        for f in findings:
            vc = f.get("vuln_class", -1)
            phases = VULN_TO_KILLCHAIN.get(vc, [])
            for phase in phases:
                finding_phases.append((phase, f))

        # Sort by phase order
        finding_phases.sort(key=lambda x: phase_order.index(x[0]))

        # Build chain — one step per phase (first finding that enables it)
        for phase, finding in finding_phases:
            if phase in covered_phases:
                continue

            confidence = finding.get("confidence", 0.5)
            severity = finding.get("severity", "low")
            success_prob = self.SEVERITY_TO_SUCCESS.get(severity, 0.3) * confidence

            # Stealth actors have lower detection probability
            detection_prob = 0.5
            if actor.stealth:
                detection_prob = 0.2
            if severity == "critical":
                detection_prob *= 1.5  # Critical exploits are noisier

            step = KillChainStep(
                phase=phase,
                technique=f"Exploit {finding.get('vulnerability_name', 'Unknown')}",
                finding_ref=f"{finding.get('filepath', '?')}:{finding.get('line', 0)}",
                vuln_class=finding.get("vuln_class", -1),
                description=f"Use {finding.get('vulnerability_name', 'vulnerability')} to achieve {phase.name.lower().replace('_', ' ')}",
                success_probability=min(0.99, success_prob),
                detection_probability=min(0.99, detection_prob),
            )

            steps.append(step)
            covered_phases.add(phase)

            # Limit chain length based on actor patience
            if len(steps) >= min(8, actor.time_budget_hours):
                break

        return steps

    def _generate_attack_narrative(
        self, actor: ThreatActor, chain: list[KillChainStep], findings: list[dict]
    ) -> str:
        """Generate a readable attack story."""
        if not chain:
            return f"{actor.name} finds no viable attack path."

        parts = [f"A {actor.name.lower()} (motivated by {actor.motivation.lower()}) attacks the application:"]

        for i, step in enumerate(chain, 1):
            parts.append(
                f"  Step {i} ({step.phase.name}): {step.description} "
                f"[Success: {step.success_probability:.0%}]"
            )

        success = 1.0
        for s in chain:
            success *= s.success_probability

        parts.append(
            f"\nOverall chain success probability: {success:.1%}. "
            f"Phases covered: {len(set(s.phase for s in chain))}/{len(KillChainPhase)}."
        )

        return "\n".join(parts)

    def _suggest_countermeasures(self, chain: list[KillChainStep]) -> list[str]:
        """Suggest countermeasures that would break the attack chain."""
        countermeasures = set()

        phase_countermeasures = {
            KillChainPhase.RECONNAISSANCE: "Minimize information disclosure and error verbosity",
            KillChainPhase.INITIAL_ACCESS: "Implement WAF, input validation, and multi-factor authentication",
            KillChainPhase.EXECUTION: "Deploy application sandboxing and process isolation",
            KillChainPhase.PERSISTENCE: "Monitor for unauthorized file/config changes",
            KillChainPhase.PRIVILEGE_ESCALATION: "Implement principle of least privilege and RBAC",
            KillChainPhase.DEFENSE_EVASION: "Deploy comprehensive logging and SIEM integration",
            KillChainPhase.CREDENTIAL_ACCESS: "Use hardware security keys and credential rotation",
            KillChainPhase.DISCOVERY: "Network segmentation and access controls",
            KillChainPhase.LATERAL_MOVEMENT: "Microsegmentation and zero-trust architecture",
            KillChainPhase.COLLECTION: "Data loss prevention (DLP) and classification",
            KillChainPhase.EXFILTRATION: "Egress filtering and network monitoring",
            KillChainPhase.IMPACT: "Immutable backups and disaster recovery",
        }

        for step in chain:
            cm = phase_countermeasures.get(step.phase)
            if cm:
                countermeasures.add(cm)

        return sorted(countermeasures)

    def _build_risk_matrix(self, findings: list[dict]) -> dict:
        """Build a risk matrix showing actor level vs. impact."""
        matrix = {}

        for level in ThreatActorLevel:
            actor = THREAT_ACTORS[level]
            exploitable = self._filter_exploitable(actor, findings)

            max_sev = "none"
            for f in exploitable:
                sev = f.get("severity", "low")
                if sev == "critical":
                    max_sev = "critical"
                elif sev == "high" and max_sev not in ("critical",):
                    max_sev = "high"
                elif sev == "medium" and max_sev not in ("critical", "high"):
                    max_sev = "medium"
                elif sev == "low" and max_sev == "none":
                    max_sev = "low"

            matrix[level.name] = {
                "exploitable_findings": len(exploitable),
                "max_impact": max_sev,
                "actor_name": actor.name,
            }

        return matrix

    def _identify_priority_targets(self, findings: list[dict]) -> list[dict]:
        """Identify files/components that are priority targets for attackers."""
        file_risk: dict[str, dict] = {}

        for f in findings:
            fp = f.get("filepath", "unknown")
            if fp not in file_risk:
                file_risk[fp] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}

            sev = f.get("severity", "low")
            file_risk[fp][sev] = file_risk[fp].get(sev, 0) + 1
            file_risk[fp]["total"] += 1

        # Score and rank
        priority = []
        for fp, counts in file_risk.items():
            score = counts["critical"] * 10 + counts["high"] * 5 + counts["medium"] * 2 + counts["low"]
            if score > 0:
                priority.append({
                    "filepath": fp,
                    "risk_score": score,
                    "critical": counts["critical"],
                    "high": counts["high"],
                    "total_findings": counts["total"],
                })

        priority.sort(key=lambda x: x["risk_score"], reverse=True)
        return priority[:20]

    def get_simulation_summary(self) -> str:
        """Format simulation results as human-readable report."""
        lines = [
            "",
            "  +==============================================================+",
            "  |        BAYREUTHWING -- Adversarial Simulation Report         |",
            "  +==============================================================+",
            "",
        ]

        for sim in self.simulations:
            marker = "[!!]" if sim.max_impact in ("critical", "high") else "[!]" if sim.max_impact == "medium" else "[.]" 
            lines.append(
                f"  {marker} {sim.actor.name:<30} "
                f"Steps: {sim.total_steps:<3} "
                f"Success: {sim.overall_success_probability:.0%}  "
                f"Impact: {sim.max_impact.upper()}"
            )

        lines.append("")

        if self.simulations:
            worst = max(self.simulations, key=lambda s: s.overall_success_probability)
            if worst.countermeasures:
                lines.append("  PRIORITY COUNTERMEASURES:")
                lines.append("  " + "-" * 58)
                for cm in worst.countermeasures[:5]:
                    lines.append(f"    -> {cm}")
                lines.append("")

        return "\n".join(lines)
