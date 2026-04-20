"""
BAYREUTHWING — Hybrid Scan Engine v2.0 (Mythos-Class)

The core orchestrator that combines ML inference, static rules, code flow
analysis, dynamic rules, MiroFish scenario execution, cognitive reasoning,
adversarial simulation, self-evolution, and internet-connected discovery
into a unified, self-improving scanning pipeline.

Architecture:
    ┌──────────────────────────────────────────────────────────────────────┐
    │                    BAYREUTHWING SCAN ENGINE v2.0                    │
    ├──────────────────────────────────────────────────────────────────────┤
    │                                                                     │
    │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
    │  │   ML     │ │  Static  │ │  Code    │ │  Reverse │ │ Dynamic  │ │
    │  │ Inference│ │  Rules   │ │  Flow    │ │  Engrng  │ │  Rules   │ │
    │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ │
    │       └────────────┼────────────┼────────────┼────────────┘       │
    │              ┌─────▼────────────▼────────────▼──────┐             │
    │              │     Finding Merger & Deduplicator     │             │
    │              └─────┬────────────────────────────────┘             │
    │              ┌─────▼────────────────────────────────┐             │
    │              │     MiroFish Scenario Execution       │             │
    │              │     (Multi-Dimensional Deep Scan)     │             │
    │              └─────┬────────────────────────────────┘             │
    │              ┌─────▼────────────────────────────────┐             │
    │              │     Cognitive Reasoning Engine        │             │
    │              │     (Correlation + Attack Paths)      │             │
    │              └─────┬────────────────────────────────┘             │
    │              ┌─────▼────────────────────────────────┐             │
    │              │     Adversarial Simulation Engine     │             │
    │              │     (Kill Chain + Threat Actors)      │             │
    │              └─────┬────────────────────────────────┘             │
    │              ┌─────▼────────────────────────────────┐             │
    │              │     Self-Evolution Engine             │             │
    │              │     (Pattern Learning + Auto-Tune)    │             │
    │              └─────┬────────────────────────────────┘             │
    │              ┌─────▼────────────────────────────────┐             │
    │              │     Internet Discovery (Optional)     │             │
    │              │     (NVD/CVE + Zero-Day Research)     │             │
    │              └──────────────────────────────────────┘             │
    └──────────────────────────────────────────────────────────────────────┘
"""

import os
import time
try:
    import torch
except ImportError:
    torch = None
from typing import Optional
from pathlib import Path

from ..model.transformer import CodeTransformer
from ..model.tokenizer import CodeTokenizer
from ..scanner.rules import RuleEngine
from ..scanner.analyzer import CodeAnalyzer
from ..utils.cwe_mapping import CWEMapper
from ..utils.helpers import (
    find_code_files,
    read_file_safe,
    detect_file_language,
    get_line_context,
)
from ..utils.logger import setup_logger


class Finding:
    """Represents a single security finding."""

    def __init__(
        self,
        vuln_class: int,
        filepath: str,
        line: int,
        message: str,
        severity: str,
        confidence: float,
        source: str,
        matched_text: str = "",
        rule_id: str = "",
    ):
        self.vuln_class = vuln_class
        self.filepath = filepath
        self.line = line
        self.message = message
        self.severity = severity
        self.confidence = confidence
        self.source = source
        self.matched_text = matched_text
        self.rule_id = rule_id

        # Enrich with CWE/OWASP data
        info = CWEMapper.get_info(vuln_class)
        self.vulnerability_name = info.get("name", f"Unknown ({vuln_class})")
        self.cwe_id = info.get("cwe_id", "Unknown")
        self.owasp = info.get("owasp", "Unknown")
        self.remediation = info.get("remediation", [])

    def to_dict(self) -> dict:
        return {
            "vuln_class": self.vuln_class,
            "vulnerability_name": self.vulnerability_name,
            "cwe_id": self.cwe_id,
            "owasp": self.owasp,
            "filepath": self.filepath,
            "line": self.line,
            "message": self.message,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "source": self.source,
            "rule_id": self.rule_id,
            "matched_text": self.matched_text,
            "remediation": self.remediation,
        }


class ScanEngine:
    """
    Mythos-Class multi-agent hybrid scanning engine.

    Combines eight analysis modules into a unified, self-improving pipeline:
    1. ML Inference — CodeTransformer 100M-parameter predictions
    2. Static Rules — 200+ regex pattern rules
    3. Code Analyzer — Flow analysis and missing controls
    4. Reverse Engineering — Binary/API/route analysis
    5. Dynamic Rules — Hot-loadable, self-tuning rules engine
    6. MiroFish Deep Scan — Multi-dimensional scenario execution
    7. Cognitive Engine — Cross-finding correlation and reasoning
    8. Adversarial Simulation — MITRE ATT&CK kill chain modeling
    9. Self-Evolution — Autonomous pattern discovery and tuning
    10. Internet Discovery — NVD/CVE zero-day research (optional)

    Findings are merged, deduplicated, correlated, and severity-scored.
    """

    def __init__(
        self,
        model: Optional[CodeTransformer] = None,
        tokenizer: Optional[CodeTokenizer] = None,
        config: Optional[dict] = None,
        model_path: Optional[str] = None,
        enable_deep_scan: bool = False,
        enable_cognitive: bool = True,
        enable_adversarial: bool = True,
        enable_evolution: bool = True,
        enable_discovery: bool = False,
    ):
        """
        Args:
            model: Pre-loaded CodeTransformer model.
            tokenizer: Pre-loaded CodeTokenizer.
            config: Scanner configuration dictionary.
            model_path: Path to model checkpoint.
            enable_deep_scan: Enable MiroFish deep scenario execution.
            enable_cognitive: Enable cognitive reasoning engine.
            enable_adversarial: Enable adversarial simulation.
            enable_evolution: Enable self-evolution engine.
            enable_discovery: Enable internet-connected discovery.
        """
        self.config = config or {}
        scanner_cfg = self.config.get("scanner", self.config)
        self.logger = setup_logger("bayreuthwing.scanner")

        # ── ML Model (optional — scanner works without it) ────────
        self.model = model
        self.tokenizer = tokenizer or CodeTokenizer()
        if torch:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = None

        if model_path and not model:
            self._load_model(model_path)

        if self.model and self.device:
            self.model.to(self.device)
            self.model.eval()

        # ── Static rule engine ────────────────────────────────────
        self.rule_engine = RuleEngine()

        # ── Code flow analyzer ────────────────────────────────────
        self.code_analyzer = CodeAnalyzer()
        from .reversing.analyzer import ReverseEngineeringAnalyzer
        self.reverse_engineering_analyzer = ReverseEngineeringAnalyzer()

        # ── Dynamic rules engine ──────────────────────────────────
        self.dynamic_rules_engine = None
        try:
            from .dynamic_rules import DynamicRuleEngine
            self.dynamic_rules_engine = DynamicRuleEngine(
                config=self.config.get("dynamic_rules", {})
            )
            self.logger.info(f"Dynamic rules engine loaded: {self.dynamic_rules_engine.stats()['active_rules']} active rules")
        except Exception as e:
            self.logger.debug(f"Dynamic rules engine not available: {e}")

        # ── MiroFish Deep Scan ────────────────────────────────────
        self.enable_deep_scan = enable_deep_scan
        self.mirofish_engine = None
        self.scenario_executor = None
        self.adaptive_learning = None
        if self.enable_deep_scan:
            try:
                from .reversing.mirofish import MiroFishEngine
                from .reversing.scenario_executor import ScenarioExecutor
                from .reversing.adaptive_learning import AdaptiveLearningStore
                self.mirofish_engine = MiroFishEngine()
                self.scenario_executor = ScenarioExecutor()
                self.adaptive_learning = AdaptiveLearningStore()
                self.logger.info("MiroFish deep scan engine loaded")
            except Exception as e:
                self.logger.debug(f"MiroFish not available: {e}")
                self.enable_deep_scan = False

        # ── Cognitive Reasoning Engine ────────────────────────────
        self.enable_cognitive = enable_cognitive
        self.cognitive_engine = None
        if self.enable_cognitive:
            try:
                from .cognitive_engine import CognitiveEngine
                self.cognitive_engine = CognitiveEngine(config=self.config)
                self.logger.info("Cognitive reasoning engine loaded")
            except Exception as e:
                self.logger.debug(f"Cognitive engine not available: {e}")
                self.enable_cognitive = False

        # ── Adversarial Simulation ────────────────────────────────
        self.enable_adversarial = enable_adversarial
        self.adversarial_sim = None
        if self.enable_adversarial:
            try:
                from .adversarial_sim import AdversarialSimulator
                self.adversarial_sim = AdversarialSimulator(config=self.config)
                self.logger.info("Adversarial simulation engine loaded")
            except Exception as e:
                self.logger.debug(f"Adversarial sim not available: {e}")
                self.enable_adversarial = False

        # ── Self-Evolution Engine ─────────────────────────────────
        self.enable_evolution = enable_evolution
        self.evolution_engine = None
        if self.enable_evolution:
            try:
                from .self_evolution import SelfEvolutionEngine
                self.evolution_engine = SelfEvolutionEngine()
                self.logger.info(
                    f"Self-evolution engine loaded: "
                    f"{len(self.evolution_engine.get_active_patterns())} active evolved patterns"
                )
            except Exception as e:
                self.logger.debug(f"Evolution engine not available: {e}")
                self.enable_evolution = False

        # ── Internet Discovery (disabled by default) ──────────────
        self.enable_discovery = enable_discovery
        self.vuln_discovery = None
        if self.enable_discovery:
            try:
                from ..intel.vuln_discovery import VulnerabilityDiscovery
                self.vuln_discovery = VulnerabilityDiscovery(
                    config=self.config.get("internet_discovery", {})
                )
                self.logger.info("Internet vulnerability discovery loaded")
            except Exception as e:
                self.logger.debug(f"Vulnerability discovery not available: {e}")
                self.enable_discovery = False

        # ── Configuration ─────────────────────────────────────────
        self.confidence_threshold = scanner_cfg.get("confidence_threshold", 0.5)
        self.max_file_size_kb = scanner_cfg.get("max_file_size_kb", 5120)

        # Module activation (admin control)
        modules = scanner_cfg.get("modules", {})
        self.enable_ml = self.model is not None
        self.enable_rules = modules.get("code_analysis", {}).get("enabled", True)
        self.enable_flow = modules.get("architecture_analysis", {}).get("enabled", True)
        self.enable_deps = modules.get("dependency_analysis", {}).get("enabled", True)

    def _load_model(self, model_path: str):
        """Load model from checkpoint."""
        if not os.path.exists(model_path):
            self.logger.warning(f"Model not found at {model_path} — using rules-only mode")
            return

        try:
            checkpoint = torch.load(model_path, map_location=self.device)
            config = checkpoint.get("config", {})
            self.model = CodeTransformer.from_config(config)
            self.model.load_state_dict(checkpoint["model_state_dict"])
            self.logger.info(f"Model loaded from {model_path}")
        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            self.model = None

    def scan_file(self, filepath: str) -> list[Finding]:
        """
        Scan a single file for vulnerabilities using all active modules.

        Args:
            filepath: Path to the code file.

        Returns:
            List of Finding objects.
        """
        code = read_file_safe(filepath)
        if code is None:
            self.logger.warning(f"Could not read: {filepath}")
            return []

        language = detect_file_language(filepath)
        findings = []

        # ── Module 1: ML Inference ──────────────────────────
        if self.enable_ml and self.model:
            ml_findings = self._ml_scan(code, filepath)
            findings.extend(ml_findings)

        # ── Module 2: Static Rules ──────────────────────────
        if self.enable_rules:
            rule_findings = self._rule_scan(code, filepath, language)
            findings.extend(rule_findings)

        # ── Module 3: Code Flow Analysis ────────────────────
        if self.enable_flow:
            flow_findings = self._flow_scan(code, filepath)
            findings.extend(flow_findings)

        # ── Module 4: Reverse Engineering ───────────────────
        if hasattr(self, 'reverse_engineering_analyzer'):
            rev_findings = self._reversing_scan(code, filepath, language)
            findings.extend(rev_findings)

        # ── Module 5: Dynamic Rules ─────────────────────────
        if self.dynamic_rules_engine:
            dyn_findings = self._dynamic_rule_scan(code, filepath, language)
            findings.extend(dyn_findings)

        # ── Module 6: Evolved Patterns ──────────────────────
        if self.evolution_engine:
            evo_findings = self._evolved_pattern_scan(code, filepath)
            findings.extend(evo_findings)

        # ── Merge & Deduplicate ─────────────────────────────
        findings = self._merge_findings(findings)

        # ── Apply severity thresholds ───────────────────────
        findings = [
            f for f in findings if f.confidence >= self.confidence_threshold
        ]

        # ── Sort by severity (critical first) ───────────────
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda f: (severity_order.get(f.severity, 4), -f.confidence))

        return findings

    def scan_directory(
        self,
        path: str,
        recursive: bool = True,
        progress_callback=None,
    ) -> dict:
        """
        Scan all code files in a directory with full intelligence pipeline.

        Args:
            path: Directory path.
            recursive: Scan subdirectories.
            progress_callback: Optional callback(current, total, filepath).

        Returns:
            Comprehensive scan results dictionary with intelligence layers.
        """
        start_time = time.time()
        files = find_code_files(path, recursive=recursive)
        total_files = len(files)

        all_findings = []
        file_results = {}
        scanned = 0
        errors = 0

        # Start adaptive learning scan memory
        scan_id = None
        if self.adaptive_learning:
            scan_id = self.adaptive_learning.start_scan_memory(path)

        for i, filepath in enumerate(files, 1):
            if progress_callback:
                progress_callback(i, total_files, filepath)

            try:
                file_findings = self.scan_file(filepath)
                file_results[filepath] = {
                    "findings": [f.to_dict() for f in file_findings],
                    "count": len(file_findings),
                }
                all_findings.extend(file_findings)
                scanned += 1
            except Exception as e:
                self.logger.error(f"Error scanning {filepath}: {e}")
                errors += 1

        elapsed = time.time() - start_time

        # Build base results
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        vuln_counts = {}
        for f in all_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            vuln_counts[f.vulnerability_name] = vuln_counts.get(f.vulnerability_name, 0) + 1

        results = {
            "target": path,
            "scan_time": round(elapsed, 2),
            "files_scanned": scanned,
            "files_total": total_files,
            "errors": errors,
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "vulnerability_counts": vuln_counts,
            "findings": [f.to_dict() for f in all_findings],
            "file_results": file_results,
            "engine_info": self._get_engine_info(),
        }

        # ═══════════════════════════════════════════════════════
        # INTELLIGENCE LAYERS (post-scan analysis)
        # ═══════════════════════════════════════════════════════

        findings_dicts = [f.to_dict() for f in all_findings]

        # ── Cognitive Reasoning ─────────────────────────────
        if self.enable_cognitive and self.cognitive_engine:
            try:
                cognitive_results = self.cognitive_engine.analyze(
                    findings_dicts,
                    scan_context={"target": path, "files_scanned": scanned},
                )
                results["cognitive_analysis"] = cognitive_results
                self.logger.info(
                    f"Cognitive analysis: {len(cognitive_results.get('correlations', []))} correlations, "
                    f"{len(cognitive_results.get('attack_paths', []))} attack paths"
                )
            except Exception as e:
                self.logger.error(f"Cognitive analysis error: {e}")

        # ── Adversarial Simulation ──────────────────────────
        if self.enable_adversarial and self.adversarial_sim:
            try:
                sim_results = self.adversarial_sim.simulate(findings_dicts)
                results["adversarial_simulation"] = sim_results
                self.logger.info(
                    f"Adversarial simulation: {len(sim_results.get('simulations', []))} actor simulations"
                )
            except Exception as e:
                self.logger.error(f"Adversarial simulation error: {e}")

        # ── MiroFish Deep Scan ──────────────────────────────
        if self.enable_deep_scan and self.mirofish_engine and self.scenario_executor:
            try:
                deep_results = self._run_deep_scan(all_findings, path, files)
                results["deep_scan"] = deep_results
                self.logger.info(
                    f"MiroFish deep scan: {deep_results.get('scenarios_executed', 0)} scenarios executed"
                )
            except Exception as e:
                self.logger.error(f"MiroFish deep scan error: {e}")

        # ── Self-Evolution ──────────────────────────────────
        if self.enable_evolution and self.evolution_engine:
            try:
                evolution_report = self.evolution_engine.evolve(results)
                results["evolution_report"] = evolution_report
                self.logger.info(
                    f"Self-evolution: {len(evolution_report.get('new_patterns', []))} new patterns, "
                    f"{len(evolution_report.get('promoted_patterns', []))} promoted"
                )
            except Exception as e:
                self.logger.error(f"Self-evolution error: {e}")

        # ── Internet Discovery (optional) ───────────────────
        if self.enable_discovery and self.vuln_discovery:
            try:
                discovery_results = self._run_discovery(findings_dicts)
                results["internet_discovery"] = discovery_results
            except Exception as e:
                self.logger.error(f"Internet discovery error: {e}")

        # ── Update adaptive learning ────────────────────────
        if self.adaptive_learning and scan_id:
            try:
                self.adaptive_learning.update_scan_memory(
                    scan_id,
                    findings_count=len(all_findings),
                    strategies=[],
                    discoveries=[f.vulnerability_name for f in all_findings[:10]],
                )
                self.adaptive_learning.save()
            except Exception as e:
                self.logger.debug(f"Adaptive learning update error: {e}")

        # ── Final timing ────────────────────────────────────
        results["total_analysis_time"] = round(time.time() - start_time, 2)

        return results

    def _run_deep_scan(self, findings: list[Finding], target_path: str, files: list[str]) -> dict:
        """
        Execute MiroFish deep multi-dimensional scan.

        Converts findings into artifacts, generates scenarios from all
        dimensions, executes them, and feeds results back into adaptive learning.
        """
        from .reversing.mirofish import Artifact, ArtifactType

        # Convert findings to MiroFish artifacts
        artifacts = []
        for f in findings:
            # Map finding to nearest artifact type
            art_type = self._finding_to_artifact_type(f)
            artifact = Artifact(
                artifact_type=art_type,
                source_module=f.source,
                filepath=f.filepath,
                line=f.line,
                content=f.matched_text or f.message,
                confidence=f.confidence,
            )
            artifacts.append(artifact)

        if not artifacts:
            return {"scenarios_executed": 0, "deep_findings": []}

        # Generate scenarios from multiple dimensions
        scenarios = self.mirofish_engine.generate_scenarios(artifacts)
        multi_dim = self.mirofish_engine.generate_multi_dimensional_scenarios(artifacts)
        compound = self.mirofish_engine.generate_compound_scenarios(artifacts)

        all_scenarios = scenarios + multi_dim + compound

        # Apply adaptive learning prioritization
        if self.adaptive_learning:
            all_scenarios = self.adaptive_learning.prioritize_scenarios(all_scenarios)

        # Execute top scenarios
        max_exec = self.config.get("mirofish", {}).get("max_scenarios_per_scan", 50)
        executed = 0
        deep_findings = []

        for scenario in all_scenarios[:max_exec]:
            try:
                # Read target code
                code = read_file_safe(scenario.target_artifact.filepath)
                if not code:
                    continue

                result = self.scenario_executor.execute(scenario, code)
                executed += 1

                if result and result.get("findings"):
                    for rf in result["findings"]:
                        deep_findings.append(rf)

                    # Record success in adaptive learning
                    if self.adaptive_learning:
                        self.adaptive_learning.record_outcome(
                            scenario, result["findings"], success=True
                        )
                else:
                    if self.adaptive_learning:
                        self.adaptive_learning.record_outcome(
                            scenario, [], success=False
                        )

                    # Try mutation
                    mutated = self.mirofish_engine.mutate_scenario(
                        scenario, failure_reason="No findings produced"
                    )
                    if mutated:
                        mut_result = self.scenario_executor.execute(mutated, code)
                        if mut_result and mut_result.get("findings"):
                            deep_findings.extend(mut_result["findings"])
                            if self.adaptive_learning:
                                self.adaptive_learning.record_outcome(
                                    mutated, mut_result["findings"],
                                    success=True, is_mutation=True
                                )

            except Exception as e:
                self.logger.debug(f"Scenario execution error: {e}")

        return {
            "scenarios_generated": len(all_scenarios),
            "scenarios_executed": executed,
            "deep_findings": deep_findings,
            "deep_findings_count": len(deep_findings),
        }

    def _run_discovery(self, findings: list[dict]) -> dict:
        """Run internet-connected vulnerability discovery."""
        results = {"enrichments": [], "trending_vulns": [], "new_rules": []}

        if not self.vuln_discovery:
            return results

        try:
            # Enrich existing findings
            for f in findings[:20]:  # Limit API calls
                enrichment = self.vuln_discovery.research_pattern(
                    f.get("vulnerability_name", ""),
                    f.get("cwe_id", ""),
                )
                if enrichment:
                    results["enrichments"].append({
                        "finding_ref": f"{f.get('filepath')}:{f.get('line')}",
                        "enrichment": enrichment,
                    })

            # Check for trending vulnerabilities
            trending = self.vuln_discovery.get_trending_vulnerabilities()
            results["trending_vulns"] = trending[:10]

        except Exception as e:
            self.logger.debug(f"Discovery error: {e}")

        return results

    def _finding_to_artifact_type(self, finding: Finding):
        """Map a Finding to the closest MiroFish ArtifactType."""
        from .reversing.mirofish import ArtifactType

        vuln_to_artifact = {
            0: ArtifactType.DATA_SINK,           # SQLi
            1: ArtifactType.OUTPUT_ENCODING,     # XSS
            2: ArtifactType.DATA_SINK,           # Command Injection
            3: ArtifactType.INPUT_VALIDATION,    # Input Validation
            4: ArtifactType.AUTH_MECHANISM,       # Broken Access Control
            5: ArtifactType.CRYPTO_USAGE,        # Crypto Failures
            6: ArtifactType.CORS_CONFIG,         # Security Misconfig
            7: ArtifactType.DATA_SOURCE,         # Sensitive Data
            8: ArtifactType.SERIALIZATION_POINT, # Deserialization
            10: ArtifactType.FILE_OPERATION,     # Path Traversal
            12: ArtifactType.DATA_SINK,          # SSTI
            14: ArtifactType.AUTH_MECHANISM,      # JWT
            17: ArtifactType.NETWORK_CALL,       # SSRF
            21: ArtifactType.SERIALIZATION_POINT,# Prototype Pollution
        }
        return vuln_to_artifact.get(finding.vuln_class, ArtifactType.LOGIC_PATH)

    @torch.no_grad()
    def _ml_scan(self, code: str, filepath: str) -> list[Finding]:
        """Run ML inference on code."""
        findings = []

        try:
            encoded = self.tokenizer.encode(code, max_length=512)
            input_ids = torch.tensor([encoded["input_ids"]], dtype=torch.long).to(self.device)
            token_type_ids = torch.tensor([encoded["token_type_ids"]], dtype=torch.long).to(self.device)

            outputs = self.model(input_ids, token_type_ids=token_type_ids)
            probs = outputs["probabilities"][0].cpu()
            confidence = outputs["confidence"][0].cpu()

            for vuln_id in range(len(probs)):
                prob = probs[vuln_id].item()
                conf = confidence[vuln_id].item()

                if prob >= self.confidence_threshold:
                    findings.append(Finding(
                        vuln_class=vuln_id,
                        filepath=filepath,
                        line=0,  # ML doesn't give line-level precision
                        message=f"ML model detected potential {CWEMapper.get_info(vuln_id).get('name', 'vulnerability')}",
                        severity=CWEMapper.get_severity(vuln_id),
                        confidence=prob * conf,
                        source="ml_model",
                    ))

        except Exception as e:
            self.logger.debug(f"ML scan error for {filepath}: {e}")

        return findings

    def _rule_scan(self, code: str, filepath: str, language: str) -> list[Finding]:
        """Run static rule matching on code."""
        findings = []
        raw_findings = self.rule_engine.scan(code, language)

        for rf in raw_findings:
            findings.append(Finding(
                vuln_class=rf["vuln_class"],
                filepath=filepath,
                line=rf["line"],
                message=rf["message"],
                severity=rf["severity"],
                confidence=rf["confidence"],
                source="static_rule",
                matched_text=rf.get("matched_text", ""),
                rule_id=rf.get("rule_id", ""),
            ))

        return findings

    def _flow_scan(self, code: str, filepath: str) -> list[Finding]:
        """Run code flow analysis."""
        findings = []
        results = self.code_analyzer.analyze(code, filepath)

        for ff in results.get("findings", []):
            findings.append(Finding(
                vuln_class=ff["vuln_class"],
                filepath=filepath,
                line=ff.get("line", 0),
                message=ff["message"],
                severity=ff["severity"],
                confidence=ff.get("confidence", 0.5),
                source=ff.get("source", "code_analysis"),
            ))

        return findings

    def _reversing_scan(self, code: str, filepath: str, language: str) -> list[Finding]:
        """Run reverse engineering analysis."""
        findings = []
        try:
            results = self.reverse_engineering_analyzer.analyze(code, filepath, language)
            for rf in results:
                findings.append(Finding(
                    vuln_class=rf.get("vuln_class", 9),
                    filepath=filepath,
                    line=rf.get("line", 0),
                    message=rf.get("message", "Reverse engineering issue found"),
                    severity=rf.get("severity", "medium"),
                    confidence=rf.get("confidence", 0.6),
                    source=rf.get("source", "reverse_engineering"),
                ))
        except Exception as e:
            self.logger.error(f"Error in reverse engineering scan for {filepath}: {e}")
        return findings

    def _dynamic_rule_scan(self, code: str, filepath: str, language: str) -> list[Finding]:
        """Run dynamic rules engine scan."""
        findings = []
        try:
            raw = self.dynamic_rules_engine.scan(code, filepath, language)
            for rf in raw:
                findings.append(Finding(
                    vuln_class=rf.get("vuln_class", 0),
                    filepath=filepath,
                    line=rf.get("line", 0),
                    message=rf.get("message", "Dynamic rule match"),
                    severity=rf.get("severity", "medium"),
                    confidence=rf.get("confidence", 0.6),
                    source="dynamic_rule",
                    matched_text=rf.get("matched_text", ""),
                    rule_id=rf.get("rule_id", ""),
                ))
        except Exception as e:
            self.logger.debug(f"Dynamic rule scan error for {filepath}: {e}")
        return findings

    def _evolved_pattern_scan(self, code: str, filepath: str) -> list[Finding]:
        """Scan using self-evolved patterns."""
        import re
        findings = []
        try:
            active_patterns = self.evolution_engine.get_active_patterns()
            for pattern in active_patterns:
                try:
                    compiled = re.compile(pattern.regex_pattern)
                    for i, line in enumerate(code.split("\n"), 1):
                        if compiled.search(line):
                            findings.append(Finding(
                                vuln_class=pattern.vuln_class,
                                filepath=filepath,
                                line=i,
                                message=f"[EVOLVED] {pattern.name}: {pattern.description}",
                                severity=CWEMapper.get_severity(pattern.vuln_class),
                                confidence=pattern.confidence * 0.8,
                                source="evolved_pattern",
                                matched_text=line.strip()[:200],
                                rule_id=pattern.pattern_id,
                            ))
                except re.error:
                    continue
        except Exception as e:
            self.logger.debug(f"Evolved pattern scan error: {e}")
        return findings

    def _merge_findings(self, findings: list[Finding]) -> list[Finding]:
        """
        Merge and deduplicate findings from multiple sources.

        When ML and rules agree on the same vulnerability in the same file,
        boost confidence. Deduplicate findings on the same line with same class.
        """
        # Group by (filepath, vuln_class, line)
        groups: dict[tuple, list[Finding]] = {}
        for f in findings:
            key = (f.filepath, f.vuln_class, f.line)
            if key not in groups:
                groups[key] = []
            groups[key].append(f)

        merged = []
        for key, group in groups.items():
            if len(group) == 1:
                merged.append(group[0])
            else:
                # Multiple sources found the same issue — boost confidence
                best = max(group, key=lambda f: f.confidence)
                sources = set(f.source for f in group)

                # Confidence boost for cross-source agreement
                if len(sources) > 1:
                    best.confidence = min(0.99, best.confidence * 1.3)
                    best.source = " + ".join(sorted(sources))

                merged.append(best)

        return merged

    def _get_engine_info(self) -> dict:
        """Return engine configuration info."""
        info = {
            "ml_enabled": self.enable_ml,
            "rules_enabled": self.enable_rules,
            "flow_enabled": self.enable_flow,
            "total_rules": self.rule_engine.total_rules,
            "deep_scan_enabled": self.enable_deep_scan,
            "cognitive_enabled": self.enable_cognitive,
            "adversarial_enabled": self.enable_adversarial,
            "evolution_enabled": self.enable_evolution,
            "discovery_enabled": self.enable_discovery,
        }

        if self.dynamic_rules_engine:
            info["dynamic_rules_loaded"] = self.dynamic_rules_engine.stats()["active_rules"]

        if self.evolution_engine:
            info["evolved_patterns_active"] = len(self.evolution_engine.get_active_patterns())

        return info

    def get_intelligence_report(self) -> str:
        """Generate a comprehensive intelligence report from all engines."""
        lines = [
            "",
            "  ╔══════════════════════════════════════════════════════════════════╗",
            "  ║              BAYREUTHWING v2.0 — Intelligence Report            ║",
            "  ║                     [ MYTHOS-CLASS ENGINE ]                     ║",
            "  ╚══════════════════════════════════════════════════════════════════╝",
            "",
            "  ACTIVE MODULES:",
            f"    ML Inference (100M params):  {'✓ ACTIVE' if self.enable_ml else '✗ Inactive'}",
            f"    Static Rules:               {'✓ ACTIVE' if self.enable_rules else '✗ Inactive'}",
            f"    Code Flow Analysis:          {'✓ ACTIVE' if self.enable_flow else '✗ Inactive'}",
            f"    Reverse Engineering:         ✓ ACTIVE",
            f"    Dynamic Rules:              {'✓ ACTIVE' if self.dynamic_rules_engine else '✗ Inactive'}",
            f"    MiroFish Deep Scan:          {'✓ ACTIVE' if self.enable_deep_scan else '✗ Inactive'}",
            f"    Cognitive Reasoning:         {'✓ ACTIVE' if self.enable_cognitive else '✗ Inactive'}",
            f"    Adversarial Simulation:      {'✓ ACTIVE' if self.enable_adversarial else '✗ Inactive'}",
            f"    Self-Evolution:             {'✓ ACTIVE' if self.enable_evolution else '✗ Inactive'}",
            f"    Internet Discovery:          {'✓ ACTIVE' if self.enable_discovery else '✗ Inactive'}",
            "",
        ]

        if self.cognitive_engine:
            lines.append(self.cognitive_engine.get_reasoning_summary())

        if self.adversarial_sim:
            lines.append(self.adversarial_sim.get_simulation_summary())

        if self.evolution_engine:
            lines.append(self.evolution_engine.get_evolution_report())

        if self.adaptive_learning:
            stats = self.adaptive_learning.get_stats()
            lines.append(self.adaptive_learning.format_stats_report(stats))

        return "\n".join(lines)
