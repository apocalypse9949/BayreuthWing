"""
BAYREUTHWING — Hybrid Scan Engine

The core orchestrator that combines ML inference, static rules, and code
flow analysis into a unified scanning pipeline. Implements the multi-agent
architecture where specialized analysis modules collaborate.

Architecture:
    ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
    │  ML Inference     │    │  Static Rules     │    │  Code Analyzer   │
    │  (CodeTransformer)│    │  (200+ patterns)  │    │  (Flow Analysis) │
    └────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘
             └────────────┬──────────┴────────────┬──────────┘
                  ┌───────▼──────────────────────▼─────────┐
                  │        Finding Merger & Deduplicator     │
                  │        (Confidence Boosting)             │
                  └───────┬─────────────────────────────────┘
                  ┌───────▼─────────────────────────────────┐
                  │        Severity Calculator               │
                  └─────────────────────────────────────────┘
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
    Multi-agent hybrid scanning engine.
    
    Combines three analysis modules:
    1. ML Inference — CodeTransformer predictions
    2. Static Rules — 200+ regex pattern rules
    3. Code Analyzer — Flow analysis and missing controls
    
    Findings are merged, deduplicated, and severity-scored.
    """

    def __init__(
        self,
        model: Optional[CodeTransformer] = None,
        tokenizer: Optional[CodeTokenizer] = None,
        config: Optional[dict] = None,
        model_path: Optional[str] = None,
    ):
        """
        Args:
            model: Pre-loaded CodeTransformer model (for ML-enhanced scanning).
            tokenizer: Pre-loaded CodeTokenizer.
            config: Scanner configuration dictionary.
            model_path: Path to model checkpoint (alternative to passing model).
        """
        self.config = config or {}
        scanner_cfg = self.config.get("scanner", self.config)
        self.logger = setup_logger("bayreuthwing.scanner")

        # ML Model (optional — scanner works without it)
        self.model = model
        self.tokenizer = tokenizer or CodeTokenizer()
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        if model_path and not model:
            self._load_model(model_path)

        if self.model:
            self.model.to(self.device)
            self.model.eval()

        # Static rule engine
        self.rule_engine = RuleEngine()

        # Code flow analyzer
        self.code_analyzer = CodeAnalyzer()
        from .reversing.analyzer import ReverseEngineeringAnalyzer
        self.reverse_engineering_analyzer = ReverseEngineeringAnalyzer()

        # Configuration
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
            # [SECURITY] Use weights_only=True to prevent arbitrary code execution during deserialization
            checkpoint = torch.load(model_path, map_location=self.device, weights_only=True)
            config = checkpoint.get("config", {})
            self.model = CodeTransformer.from_config(config)
            self.model.load_state_dict(checkpoint["model_state_dict"])
            self.logger.info(f"Model loaded from {model_path}")
        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            self.model = None

    def scan_file(self, filepath: str) -> list[Finding]:
        """
        Scan a single file for vulnerabilities.
        
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
        Scan all code files in a directory.
        
        Args:
            path: Directory path.
            recursive: Scan subdirectories.
            progress_callback: Optional callback(current, total, filepath).
            
        Returns:
            Scan results dictionary.
        """
        start_time = time.time()
        files = find_code_files(path, recursive=recursive)
        total_files = len(files)

        all_findings = []
        file_results = {}
        scanned = 0
        errors = 0

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

        # Build summary
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        vuln_counts = {}
        for f in all_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            vuln_counts[f.vulnerability_name] = vuln_counts.get(f.vulnerability_name, 0) + 1

        return {
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
            "engine_info": {
                "ml_enabled": self.enable_ml,
                "rules_enabled": self.enable_rules,
                "flow_enabled": self.enable_flow,
                "total_rules": self.rule_engine.total_rules,
            },
        }

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
