"""
BAYREUTHWING — Adaptive Learning Layer

Persistent memory system that records which analysis strategies work and
evolves the scanner's behavior over time. The scanner learns from every scan,
prioritizing techniques that previously exposed hidden logic or vulnerabilities,
and mutating strategies when they fail.

Architecture:
    ┌─────────────────────────┐
    │  Scan Execution         │
    │  (Scenario Executor)    │
    └──────────┬──────────────┘
               │ outcomes
    ┌──────────▼──────────────┐
    │  AdaptiveLearningStore  │
    │  - record_outcome()     │
    │  - prioritize_scenarios │
    │  - decay old data       │
    └──────────┬──────────────┘
               │ persist
    ┌──────────▼──────────────┐
    │  ~/.bayreuthwing/       │
    │  adaptive_state.json    │
    └─────────────────────────┘

Self-Improvement Loop:
    1. Record successful vulnerability discovery paths
    2. Learn patterns from previous scans
    3. Prioritize strategies that previously exposed hidden logic
    4. Mutate analysis strategies when a technique fails
    5. Decay old learnings to adapt to changing codebases
"""

import json
import os
import time
import hashlib
import threading
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from .mirofish import Scenario, StrategyType, ArtifactType


# ═══════════════════════════════════════════════════════════════
# STRATEGY RECORD — What the system remembers about each strategy
# ═══════════════════════════════════════════════════════════════

@dataclass
class StrategyRecord:
    """Performance record for a single analysis strategy."""
    strategy_name: str
    total_executions: int = 0
    successful_executions: int = 0       # Produced at least one finding
    total_findings_produced: int = 0      # Total findings across all runs
    high_value_findings: int = 0          # Critical/high severity findings
    mutation_successes: int = 0           # Times a mutation improved results
    last_used_timestamp: float = 0.0
    first_used_timestamp: float = 0.0
    consecutive_failures: int = 0         # Resets on success
    avg_confidence: float = 0.0           # Average confidence of findings

    # Per-artifact-type effectiveness
    effectiveness_by_artifact: dict = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        if self.total_executions == 0:
            return 0.5  # Unknown = neutral
        return self.successful_executions / self.total_executions

    @property
    def findings_per_execution(self) -> float:
        if self.total_executions == 0:
            return 0.0
        return self.total_findings_produced / self.total_executions

    @property
    def high_value_rate(self) -> float:
        if self.total_findings_produced == 0:
            return 0.0
        return self.high_value_findings / self.total_findings_produced

    def to_dict(self) -> dict:
        return {
            "strategy_name": self.strategy_name,
            "total_executions": self.total_executions,
            "successful_executions": self.successful_executions,
            "total_findings_produced": self.total_findings_produced,
            "high_value_findings": self.high_value_findings,
            "mutation_successes": self.mutation_successes,
            "last_used_timestamp": self.last_used_timestamp,
            "first_used_timestamp": self.first_used_timestamp,
            "consecutive_failures": self.consecutive_failures,
            "avg_confidence": self.avg_confidence,
            "effectiveness_by_artifact": self.effectiveness_by_artifact,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "StrategyRecord":
        return cls(
            strategy_name=data.get("strategy_name", ""),
            total_executions=data.get("total_executions", 0),
            successful_executions=data.get("successful_executions", 0),
            total_findings_produced=data.get("total_findings_produced", 0),
            high_value_findings=data.get("high_value_findings", 0),
            mutation_successes=data.get("mutation_successes", 0),
            last_used_timestamp=data.get("last_used_timestamp", 0.0),
            first_used_timestamp=data.get("first_used_timestamp", 0.0),
            consecutive_failures=data.get("consecutive_failures", 0),
            avg_confidence=data.get("avg_confidence", 0.0),
            effectiveness_by_artifact=data.get("effectiveness_by_artifact", {}),
        )


# ═══════════════════════════════════════════════════════════════
# SCAN MEMORY — Remembers entire scan sessions
# ═══════════════════════════════════════════════════════════════

@dataclass
class ScanMemory:
    """Compressed memory of a past scan for pattern matching."""
    scan_id: str
    timestamp: float
    target_hash: str             # Hash of target path
    total_findings: int = 0
    strategies_used: list = field(default_factory=list)
    key_discoveries: list = field(default_factory=list)  # What was found
    effective_chains: list = field(default_factory=list)  # Strategy sequences that worked

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ScanMemory":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ═══════════════════════════════════════════════════════════════
# ADAPTIVE LEARNING STORE
# ═══════════════════════════════════════════════════════════════

class AdaptiveLearningStore:
    """
    The persistent learning brain.

    Tracks strategy performance across scans and uses that history to
    prioritize future analysis. Like a security researcher who remembers
    what worked before and tries those techniques first.

    Scoring Formula:
        priority = base_priority
                 × success_rate_factor
                 × recency_factor
                 × findings_yield_factor
                 × high_value_bonus
                 × failure_penalty
    """

    DEFAULT_STATE_DIR = os.path.expanduser("~/.bayreuthwing")
    DEFAULT_STATE_FILE = "adaptive_state.json"

    # Scoring weights
    RECENCY_DECAY_DAYS = 30        # Half-life of recency bonus
    HIGH_VALUE_MULTIPLIER = 1.5     # Bonus for strategies that find criticals
    FAILURE_PENALTY_BASE = 0.85     # Per consecutive failure
    MAX_FAILURE_PENALTY = 0.3       # Floor — never fully disable a strategy
    UNKNOWN_STRATEGY_BOOST = 1.1    # Slight bonus for untried strategies
    MAX_SCAN_MEMORIES = 100         # Keep last N scan memories

    def __init__(self, state_dir: str | None = None, state_file: str | None = None):
        self.state_dir = state_dir or self.DEFAULT_STATE_DIR
        self.state_file = state_file or self.DEFAULT_STATE_FILE
        self.state_path = os.path.join(self.state_dir, self.state_file)
        self._lock = threading.Lock()

        # In-memory state
        self.strategy_records: dict[str, StrategyRecord] = {}
        self.scan_memories: list[ScanMemory] = []
        self.metadata: dict = {
            "version": "1.0.0",
            "total_scans": 0,
            "total_findings_ever": 0,
            "created_at": time.time(),
            "last_updated": time.time(),
        }

        # Load persisted state
        self.load()

    def load(self):
        """Load adaptive state from disk."""
        with self._lock:
            if not os.path.exists(self.state_path):
                return

            try:
                with open(self.state_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                self.metadata = data.get("metadata", self.metadata)

                for name, record_data in data.get("strategy_records", {}).items():
                    self.strategy_records[name] = StrategyRecord.from_dict(record_data)

                for mem_data in data.get("scan_memories", []):
                    self.scan_memories.append(ScanMemory.from_dict(mem_data))

            except (json.JSONDecodeError, KeyError, TypeError):
                # Corrupted state — start fresh but don't delete
                pass

    def save(self):
        """Persist adaptive state to disk."""
        with self._lock:
            os.makedirs(self.state_dir, exist_ok=True)

            self.metadata["last_updated"] = time.time()

            data = {
                "metadata": self.metadata,
                "strategy_records": {
                    name: record.to_dict()
                    for name, record in self.strategy_records.items()
                },
                "scan_memories": [
                    mem.to_dict()
                    for mem in self.scan_memories[-self.MAX_SCAN_MEMORIES:]
                ],
            }

            # Atomic write
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

    def record_outcome(
        self,
        scenario: Scenario,
        findings: list[dict],
        success: bool,
        is_mutation: bool = False,
    ):
        """
        Record the outcome of executing a scenario.

        Args:
            scenario: The executed scenario.
            findings: List of finding dicts produced.
            success: Whether the scenario produced useful results.
            is_mutation: Whether this was a mutated retry.
        """
        name = scenario.strategy.name
        now = time.time()

        with self._lock:
            if name not in self.strategy_records:
                self.strategy_records[name] = StrategyRecord(
                    strategy_name=name,
                    first_used_timestamp=now,
                )

            record = self.strategy_records[name]
            record.total_executions += 1
            record.last_used_timestamp = now

            if success:
                record.successful_executions += 1
                record.consecutive_failures = 0
                record.total_findings_produced += len(findings)

                # Count high-value findings
                high_value = sum(
                    1 for f in findings
                    if f.get("severity") in ("critical", "high")
                )
                record.high_value_findings += high_value

                # Update average confidence
                if findings:
                    avg_conf = sum(f.get("confidence", 0.5) for f in findings) / len(findings)
                    record.avg_confidence = (
                        record.avg_confidence * 0.7 + avg_conf * 0.3
                    )

                # Track effectiveness per artifact type
                art_type = scenario.target_artifact.artifact_type.name
                if art_type not in record.effectiveness_by_artifact:
                    record.effectiveness_by_artifact[art_type] = {"success": 0, "fail": 0}
                record.effectiveness_by_artifact[art_type]["success"] += 1

                if is_mutation:
                    record.mutation_successes += 1
            else:
                record.consecutive_failures += 1
                art_type = scenario.target_artifact.artifact_type.name
                if art_type not in record.effectiveness_by_artifact:
                    record.effectiveness_by_artifact[art_type] = {"success": 0, "fail": 0}
                record.effectiveness_by_artifact[art_type]["fail"] += 1

    def get_priority_score(self, strategy_name: str, artifact_type: str = "") -> float:
        """
        Calculate adaptive priority score for a strategy.

        Returns a multiplier (>1.0 = boost, <1.0 = penalize, 1.0 = neutral).
        """
        if strategy_name not in self.strategy_records:
            return self.UNKNOWN_STRATEGY_BOOST  # Slight boost for untried

        record = self.strategy_records[strategy_name]

        # 1. Success rate factor (0.5 to 1.5)
        success_factor = 0.5 + record.success_rate

        # 2. Recency factor (recent success = boost)
        if record.last_used_timestamp > 0:
            days_ago = (time.time() - record.last_used_timestamp) / 86400
            recency_factor = max(0.5, 1.0 - (days_ago / (self.RECENCY_DECAY_DAYS * 2)))
        else:
            recency_factor = 1.0

        # 3. Findings yield factor
        yield_factor = min(2.0, 1.0 + record.findings_per_execution * 0.2)

        # 4. High-value bonus
        if record.high_value_rate > 0.3:
            hv_bonus = self.HIGH_VALUE_MULTIPLIER
        elif record.high_value_rate > 0.1:
            hv_bonus = 1.2
        else:
            hv_bonus = 1.0

        # 5. Failure penalty (consecutive failures reduce priority)
        failure_penalty = max(
            self.MAX_FAILURE_PENALTY,
            self.FAILURE_PENALTY_BASE ** record.consecutive_failures,
        )

        # 6. Artifact-specific effectiveness
        art_factor = 1.0
        if artifact_type and artifact_type in record.effectiveness_by_artifact:
            art_data = record.effectiveness_by_artifact[artifact_type]
            total = art_data["success"] + art_data["fail"]
            if total > 0:
                art_factor = 0.5 + (art_data["success"] / total)

        score = success_factor * recency_factor * yield_factor * hv_bonus * failure_penalty * art_factor

        return round(score, 4)

    def prioritize_scenarios(self, scenarios: list[Scenario]) -> list[Scenario]:
        """
        Re-order scenarios using adaptive learning intelligence.

        Scenarios that historically produce more/better findings get boosted.
        Failed strategies get penalized. Unknown strategies get a slight boost.
        """
        for scenario in scenarios:
            adaptive_score = self.get_priority_score(
                scenario.strategy.name,
                scenario.target_artifact.artifact_type.name,
            )
            scenario.priority *= adaptive_score

        # Re-sort by adjusted priority
        scenarios.sort(key=lambda s: s.priority, reverse=True)
        return scenarios

    def start_scan_memory(self, target_path: str) -> str:
        """Start recording a new scan session."""
        scan_id = hashlib.sha256(
            f"{target_path}:{time.time()}".encode()
        ).hexdigest()[:12]

        target_hash = hashlib.sha256(target_path.encode()).hexdigest()[:12]

        memory = ScanMemory(
            scan_id=scan_id,
            timestamp=time.time(),
            target_hash=target_hash,
        )

        with self._lock:
            self.scan_memories.append(memory)
            self.metadata["total_scans"] = self.metadata.get("total_scans", 0) + 1

        return scan_id

    def update_scan_memory(
        self,
        scan_id: str,
        findings_count: int = 0,
        strategies: list[str] | None = None,
        discoveries: list[str] | None = None,
        effective_chains: list[list[str]] | None = None,
    ):
        """Update an ongoing scan memory."""
        with self._lock:
            for mem in self.scan_memories:
                if mem.scan_id == scan_id:
                    mem.total_findings += findings_count
                    if strategies:
                        mem.strategies_used.extend(strategies)
                    if discoveries:
                        mem.key_discoveries.extend(discoveries)
                    if effective_chains:
                        mem.effective_chains.extend(effective_chains)
                    break

    def get_stats(self) -> dict:
        """Return summary statistics for display."""
        with self._lock:
            total_strategies = len(self.strategy_records)
            total_executions = sum(r.total_executions for r in self.strategy_records.values())
            total_findings = sum(r.total_findings_produced for r in self.strategy_records.values())
            total_high_value = sum(r.high_value_findings for r in self.strategy_records.values())

            # Top strategies by success rate (min 3 executions)
            qualified = [
                r for r in self.strategy_records.values()
                if r.total_executions >= 3
            ]
            top_strategies = sorted(
                qualified,
                key=lambda r: r.success_rate * r.findings_per_execution,
                reverse=True,
            )[:10]

            # Worst performing
            worst_strategies = sorted(
                qualified,
                key=lambda r: r.success_rate,
            )[:5]

            return {
                "total_strategies_tracked": total_strategies,
                "total_executions": total_executions,
                "total_findings_produced": total_findings,
                "total_high_value_findings": total_high_value,
                "total_scans": self.metadata.get("total_scans", 0),
                "state_file": self.state_path,
                "last_updated": self.metadata.get("last_updated", 0),
                "top_strategies": [
                    {
                        "name": r.strategy_name,
                        "success_rate": f"{r.success_rate:.1%}",
                        "findings_per_run": f"{r.findings_per_execution:.1f}",
                        "high_value_rate": f"{r.high_value_rate:.1%}",
                        "total_runs": r.total_executions,
                    }
                    for r in top_strategies
                ],
                "worst_strategies": [
                    {
                        "name": r.strategy_name,
                        "success_rate": f"{r.success_rate:.1%}",
                        "consecutive_failures": r.consecutive_failures,
                        "total_runs": r.total_executions,
                    }
                    for r in worst_strategies
                ],
            }

    def format_stats_report(self, stats: dict | None = None) -> str:
        """Format stats as a human-readable report."""
        if stats is None:
            stats = self.get_stats()

        lines = [
            "",
            "  ╔══════════════════════════════════════════════════════════╗",
            "  ║       BAYREUTHWING — Adaptive Learning Intelligence    ║",
            "  ╚══════════════════════════════════════════════════════════╝",
            "",
            f"  State File:      {stats['state_file']}",
            f"  Total Scans:     {stats['total_scans']}",
            f"  Strategies:      {stats['total_strategies_tracked']}",
            f"  Executions:      {stats['total_executions']:,}",
            f"  Findings:        {stats['total_findings_produced']:,}",
            f"  High-Value:      {stats['total_high_value_findings']:,}",
            "",
        ]

        if stats["top_strategies"]:
            lines.append("  TOP PERFORMING STRATEGIES:")
            lines.append("  " + "─" * 54)
            for s in stats["top_strategies"]:
                lines.append(
                    f"    {s['name']:<35} "
                    f"SR:{s['success_rate']:>5}  "
                    f"F/R:{s['findings_per_run']:>4}  "
                    f"HV:{s['high_value_rate']:>5}  "
                    f"N:{s['total_runs']:>3}"
                )
            lines.append("")

        if stats["worst_strategies"]:
            lines.append("  UNDERPERFORMING (CANDIDATES FOR MUTATION):")
            lines.append("  " + "─" * 54)
            for s in stats["worst_strategies"]:
                lines.append(
                    f"    {s['name']:<35} "
                    f"SR:{s['success_rate']:>5}  "
                    f"CF:{s['consecutive_failures']:>2}"
                )
            lines.append("")

        return "\n".join(lines)
