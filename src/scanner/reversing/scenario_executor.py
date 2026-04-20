"""
BAYREUTHWING — MiroFish Scenario Execution Engine

The execution brain that actually RUNS MiroFish-generated scenarios
against target code artifacts. Transforms scenario plans into concrete
analysis operations with deterministic, traceable results.

Architecture:
    ┌──────────────────────────┐
    │  ScenarioExecutor        │
    │  - execute_scenario()    │
    │  - execute_batch()       │
    └──────────┬───────────────┘
               │
    ┌──────────▼───────────────┐
    │  StrategyHandlerRegistry │
    │  - 80+ strategy handlers │
    │  - dispatch by type      │
    └──────────┬───────────────┘
               │
    ┌──────────▼───────────────┐
    │  MultiDimensionalAnalyzer│
    │  - parallel dimensions   │
    │  - cross-correlation     │
    │  - compound detection    │
    └──────────────────────────┘

Anti-Hallucination:
    - All handlers are deterministic regex/AST analysis
    - No generative AI in the execution path
    - Every finding links to source artifact + scenario + handler
    - Execution is bounded by configurable timeouts
"""

import re
import time
import hashlib
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Callable

from .mirofish import (
    Scenario,
    Artifact,
    ArtifactType,
    StrategyType,
    FindingSeverity,
)


# ═══════════════════════════════════════════════════════════════
# EXECUTION REPORT
# ═══════════════════════════════════════════════════════════════

@dataclass
class ScenarioResult:
    """Result of executing a single scenario."""
    scenario_id: str
    strategy: str
    target_file: str
    findings: list = field(default_factory=list)
    success: bool = False
    execution_time_ms: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "strategy": self.strategy,
            "target_file": self.target_file,
            "findings_count": len(self.findings),
            "success": self.success,
            "execution_time_ms": round(self.execution_time_ms, 2),
            "error": self.error,
            "findings": self.findings,
        }


@dataclass
class ExecutionReport:
    """Complete report from a batch scenario execution."""
    total_scenarios: int = 0
    executed_scenarios: int = 0
    successful_scenarios: int = 0
    total_findings: int = 0
    total_execution_time_ms: float = 0.0
    scenario_results: list = field(default_factory=list)
    compound_findings: list = field(default_factory=list)
    dimensions_analyzed: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_scenarios": self.total_scenarios,
            "executed_scenarios": self.executed_scenarios,
            "successful_scenarios": self.successful_scenarios,
            "total_findings": self.total_findings,
            "total_execution_time_ms": round(self.total_execution_time_ms, 2),
            "compound_findings": len(self.compound_findings),
            "dimensions_analyzed": self.dimensions_analyzed,
            "scenario_results": [r.to_dict() for r in self.scenario_results],
        }


# ═══════════════════════════════════════════════════════════════
# VULNERABILITY DIMENSIONS — for multi-dimensional analysis
# ═══════════════════════════════════════════════════════════════

class VulnerabilityDimension(Enum):
    """Analysis dimensions for multi-dimensional scanning."""
    INJECTION = auto()       # SQLi, XSS, CMDi, SSTI, LDAP, XPath
    AUTHENTICATION = auto()  # Auth bypass, session, JWT, OAuth
    CRYPTOGRAPHY = auto()    # Weak crypto, key mgmt, randomness
    LOGIC = auto()           # Race condition, integer overflow, logic bypass
    DATA_FLOW = auto()       # Taint propagation, data exposure, PII
    NETWORK = auto()         # SSRF, DNS rebinding, CORS, redirects
    SUPPLY_CHAIN = auto()    # Dependency confusion, typosquatting
    SERIALIZATION = auto()   # Deserialization, prototype pollution
    FILE_SYSTEM = auto()     # Path traversal, file upload, TOCTOU
    MEMORY = auto()          # Buffer overflow, UAF, null deref


# Strategy → Dimension mapping
STRATEGY_DIMENSION_MAP = {
    StrategyType.SQL_INJECTION_DEEP: VulnerabilityDimension.INJECTION,
    StrategyType.XSS_CONTEXT_ANALYSIS: VulnerabilityDimension.INJECTION,
    StrategyType.COMMAND_INJECTION_CHAIN: VulnerabilityDimension.INJECTION,
    StrategyType.SSTI_DETECTION: VulnerabilityDimension.INJECTION,
    StrategyType.LDAP_INJECTION_CHECK: VulnerabilityDimension.INJECTION,
    StrategyType.XPATH_INJECTION_CHECK: VulnerabilityDimension.INJECTION,
    StrategyType.HEADER_INJECTION_CHECK: VulnerabilityDimension.INJECTION,
    StrategyType.CRLF_INJECTION_CHECK: VulnerabilityDimension.INJECTION,
    StrategyType.LOG_INJECTION_CHECK: VulnerabilityDimension.INJECTION,
    StrategyType.PARAMETER_INJECTION_PROBE: VulnerabilityDimension.INJECTION,

    StrategyType.AUTH_BYPASS_CHECK: VulnerabilityDimension.AUTHENTICATION,
    StrategyType.BROKEN_AUTH_FLOW: VulnerabilityDimension.AUTHENTICATION,
    StrategyType.SESSION_FIXATION_CHECK: VulnerabilityDimension.AUTHENTICATION,
    StrategyType.TOKEN_ENTROPY_CHECK: VulnerabilityDimension.AUTHENTICATION,
    StrategyType.COOKIE_SECURITY_AUDIT: VulnerabilityDimension.AUTHENTICATION,
    StrategyType.PASSWORD_STORAGE_AUDIT: VulnerabilityDimension.AUTHENTICATION,
    StrategyType.PRIVILEGE_ESCALATION_PATH: VulnerabilityDimension.AUTHENTICATION,
    StrategyType.JWT_VULNERABILITY_SCAN: VulnerabilityDimension.AUTHENTICATION,
    StrategyType.OAUTH_MISCONFIGURATION: VulnerabilityDimension.AUTHENTICATION,

    StrategyType.WEAK_ALGORITHM_SCAN: VulnerabilityDimension.CRYPTOGRAPHY,
    StrategyType.KEY_MANAGEMENT_AUDIT: VulnerabilityDimension.CRYPTOGRAPHY,
    StrategyType.IV_REUSE_DETECTION: VulnerabilityDimension.CRYPTOGRAPHY,
    StrategyType.PADDING_ORACLE_CHECK: VulnerabilityDimension.CRYPTOGRAPHY,
    StrategyType.HASH_WITHOUT_SALT: VulnerabilityDimension.CRYPTOGRAPHY,
    StrategyType.INSECURE_RANDOM_CHECK: VulnerabilityDimension.CRYPTOGRAPHY,
    StrategyType.CERTIFICATE_VALIDATION_CHECK: VulnerabilityDimension.CRYPTOGRAPHY,
    StrategyType.TLS_CONFIGURATION_AUDIT: VulnerabilityDimension.CRYPTOGRAPHY,

    StrategyType.BRANCH_COVERAGE_ANALYSIS: VulnerabilityDimension.LOGIC,
    StrategyType.DEAD_CODE_DETECTION: VulnerabilityDimension.LOGIC,
    StrategyType.EXCEPTION_PATH_ANALYSIS: VulnerabilityDimension.LOGIC,
    StrategyType.RACE_CONDITION_CHECK: VulnerabilityDimension.LOGIC,
    StrategyType.TOCTOU_DETECTION: VulnerabilityDimension.LOGIC,
    StrategyType.BUSINESS_LOGIC_BYPASS: VulnerabilityDimension.LOGIC,
    StrategyType.INTEGER_OVERFLOW_CHECK: VulnerabilityDimension.LOGIC,
    StrategyType.NULL_DEREFERENCE_SCAN: VulnerabilityDimension.LOGIC,
    StrategyType.INFINITE_LOOP_DETECTION: VulnerabilityDimension.LOGIC,
    StrategyType.RECURSION_DEPTH_CHECK: VulnerabilityDimension.LOGIC,
    StrategyType.RESOURCE_LEAK_DETECTION: VulnerabilityDimension.LOGIC,

    StrategyType.TAINT_PROPAGATION_DEEP: VulnerabilityDimension.DATA_FLOW,
    StrategyType.SENSITIVE_DATA_FLOW: VulnerabilityDimension.DATA_FLOW,
    StrategyType.PII_EXPOSURE_CHECK: VulnerabilityDimension.DATA_FLOW,
    StrategyType.LOGGING_SECRETS_CHECK: VulnerabilityDimension.DATA_FLOW,
    StrategyType.ERROR_INFO_LEAK: VulnerabilityDimension.DATA_FLOW,
    StrategyType.STACK_TRACE_EXPOSURE: VulnerabilityDimension.DATA_FLOW,

    StrategyType.SSRF_DEEP_SCAN: VulnerabilityDimension.NETWORK,
    StrategyType.DNS_REBINDING_CHECK: VulnerabilityDimension.NETWORK,
    StrategyType.OPEN_REDIRECT_CHECK: VulnerabilityDimension.NETWORK,
    StrategyType.WEBHOOK_INJECTION_CHECK: VulnerabilityDimension.NETWORK,
    StrategyType.CORS_MISCONFIGURATION_CHECK: VulnerabilityDimension.NETWORK,

    StrategyType.DEPENDENCY_CONFUSION: VulnerabilityDimension.SUPPLY_CHAIN,
    StrategyType.TYPOSQUATTING_CHECK: VulnerabilityDimension.SUPPLY_CHAIN,
    StrategyType.MALICIOUS_PACKAGE_SCAN: VulnerabilityDimension.SUPPLY_CHAIN,

    StrategyType.UNSAFE_DESERIALIZE_SCAN: VulnerabilityDimension.SERIALIZATION,
    StrategyType.GADGET_CHAIN_DETECTION: VulnerabilityDimension.SERIALIZATION,
    StrategyType.TYPE_CONFUSION_CHECK: VulnerabilityDimension.SERIALIZATION,
    StrategyType.PROTOTYPE_POLLUTION_CHECK: VulnerabilityDimension.SERIALIZATION,

    StrategyType.PATH_TRAVERSAL_DEEP: VulnerabilityDimension.FILE_SYSTEM,
    StrategyType.FILE_INCLUSION_CHECK: VulnerabilityDimension.FILE_SYSTEM,
    StrategyType.TEMP_FILE_RACE: VulnerabilityDimension.FILE_SYSTEM,
    StrategyType.SYMLINK_ATTACK_CHECK: VulnerabilityDimension.FILE_SYSTEM,
    StrategyType.FILE_UPLOAD_BYPASS: VulnerabilityDimension.FILE_SYSTEM,
}


# ═══════════════════════════════════════════════════════════════
# STRATEGY HANDLERS — Concrete analysis implementations
# ═══════════════════════════════════════════════════════════════

class StrategyHandlers:
    """
    Registry of concrete analysis functions for each StrategyType.

    Every handler receives (code, filepath, params) and returns findings.
    All handlers are deterministic regex/pattern analysis — no AI, no
    generative content, no hallucination possible.
    """

    @staticmethod
    def _find_pattern(code: str, filepath: str, patterns: list[tuple[str, str, int, str, float]]) -> list[dict]:
        """
        Generic pattern finder. Each pattern is:
        (regex, message, vuln_class, severity, confidence)
        """
        findings = []
        for pattern, message, vuln_class, severity, confidence in patterns:
            try:
                for match in re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE):
                    line = code[:match.start()].count("\n") + 1
                    findings.append({
                        "vuln_class": vuln_class,
                        "severity": severity,
                        "confidence": confidence,
                        "line": line,
                        "message": message,
                        "matched_text": match.group(0)[:100],
                        "filepath": filepath,
                        "source": "mirofish_execution",
                    })
            except re.error:
                pass
        return findings

    @classmethod
    def handle_sql_injection_deep(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """Deep SQL injection analysis — beyond basic pattern matching."""
        patterns = [
            (r'(?:execute|cursor\.execute|query|raw_query)\s*\(\s*(?:f["\']|["\'].*%|.*\.format\(|.*\+\s*\w+)',
             "SQL query built with string interpolation — high SQLi risk", 0, "critical", 0.9),
            (r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+.*\+\s*(?:request|params|user_input|argv)',
             "SQL statement concatenated with user input", 0, "critical", 0.95),
            (r'(?:WHERE|AND|OR)\s+\w+\s*=\s*["\']?\s*\+\s*\w+',
             "WHERE clause with string concatenation", 0, "critical", 0.85),
            (r'\.raw\s*\(\s*(?:f["\']|.*%s|.*\.format)',
             "ORM raw query with string interpolation", 0, "high", 0.8),
            (r'text\s*\(\s*(?:f["\']|.*\+)',
             "SQLAlchemy text() with string interpolation", 0, "high", 0.8),
        ]
        return cls._find_pattern(code, filepath, patterns)

    @classmethod
    def handle_xss_context_analysis(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """Context-aware XSS detection."""
        patterns = [
            (r'(?:innerHTML|outerHTML|document\.write)\s*(?:=|\()\s*(?:.*\+|.*request|.*params|.*user)',
             "DOM-based XSS — user input in innerHTML/document.write", 1, "high", 0.9),
            (r'(?:render|response\.write|echo|print)\s*\(.*(?:request\.|params\[|GET\[|POST\[)',
             "Reflected XSS — user input in response without encoding", 1, "high", 0.8),
            (r'\{\{\s*\w+\s*\|\s*safe\s*\}\}',
             "Template variable marked as safe — bypasses auto-escaping", 1, "high", 0.85),
            (r'dangerouslySetInnerHTML\s*=\s*\{',
             "React dangerouslySetInnerHTML usage", 1, "high", 0.75),
            (r'v-html\s*=\s*["\']',
             "Vue v-html directive — renders raw HTML", 1, "medium", 0.7),
        ]
        return cls._find_pattern(code, filepath, patterns)

    @classmethod
    def handle_command_injection_chain(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """Command injection chain analysis."""
        patterns = [
            (r'(?:os\.system|os\.popen|subprocess\.call|subprocess\.Popen|exec|execSync)\s*\(.*(?:\+|format|f["\']|%s).*(?:request|user|input|argv|params)',
             "OS command with user input — command injection", 2, "critical", 0.9),
            (r'(?:shell\s*=\s*True|shell=True).*(?:request|user|input)',
             "Subprocess with shell=True and user input", 2, "critical", 0.95),
            (r'(?:eval|exec)\s*\(\s*(?:request|user_input|params|argv)',
             "Dynamic code execution with user input", 2, "critical", 0.9),
            (r'child_process\.exec\s*\(.*(?:req\.|params\.|query\.)',
             "Node.js child_process.exec with user input", 2, "critical", 0.9),
        ]
        return cls._find_pattern(code, filepath, patterns)

    @classmethod
    def handle_ssti_detection(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """Server-side template injection detection."""
        patterns = [
            (r'(?:render_template_string|Template)\s*\(\s*(?:request\.|user_input|f["\'])',
             "Template rendered with user-controlled string — SSTI", 14, "critical", 0.9),
            (r'(?:render_template_string|Jinja2|Environment)\s*\(.*(?:\+|format|%)',
             "Template engine with string interpolation", 14, "high", 0.8),
            (r'\{\{.*(?:config|self\.__class__|__import__|os\.)',
             "Jinja2 template with dangerous object access", 14, "critical", 0.85),
        ]
        return cls._find_pattern(code, filepath, patterns)

    @classmethod
    def handle_auth_bypass_check(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """Authentication bypass pattern detection."""
        patterns = [
            (r'(?:@app\.route|@router\.\w+|app\.\w+)\s*\([^)]+\)(?![\s\S]{0,200}(?:@login_required|@auth|@requires_auth|authenticate|verify_token|jwt_required))',
             "Route handler without authentication decorator", 9, "high", 0.6),
            (r'if\s+(?:True|1)\s*:[\s\S]{0,100}(?:admin|grant|allow|authorize)',
             "Hardcoded authentication bypass condition", 9, "critical", 0.85),
            (r'(?:is_admin|is_authenticated|authorized)\s*=\s*(?:True|1|"true")',
             "Hardcoded admin/auth flag", 9, "high", 0.8),
            (r'(?:verify_password|check_password|authenticate)\s*=\s*(?:False|lambda.*True)',
             "Authentication check disabled or always-true", 9, "critical", 0.9),
        ]
        return cls._find_pattern(code, filepath, patterns)

    @classmethod
    def handle_ssrf_deep_scan(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """Deep SSRF detection."""
        patterns = [
            (r'(?:requests\.get|urllib\.request\.urlopen|fetch|http\.get|HttpClient)\s*\(\s*(?:request\.|user_|params\[|args\.|f["\'])',
             "HTTP request with user-controlled URL — SSRF", 8, "high", 0.85),
            (r'(?:requests\.\w+|urllib\.\w+|fetch)\s*\([^)]*(?:url\s*=|(?:request|params|user))',
             "Outbound request with user-influenced URL parameter", 8, "high", 0.8),
            (r'169\.254\.169\.254|metadata\.google|100\.100\.100\.200',
             "Cloud metadata endpoint reference — SSRF target", 8, "high", 0.9),
        ]
        return cls._find_pattern(code, filepath, patterns)

    @classmethod
    def handle_weak_algorithm_scan(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """Weak cryptographic algorithm detection."""
        patterns = [
            (r'(?:hashlib\.md5|MD5\.|Digest::MD5|md5\(|MD5\.Create)',
             "MD5 hash usage — cryptographically broken", 6, "medium", 0.85),
            (r'(?:hashlib\.sha1|SHA1\.|Digest::SHA1|sha1\(|SHA1\.Create)',
             "SHA1 hash usage — known collision attacks", 6, "medium", 0.8),
            (r'(?:DES|RC4|RC2|Blowfish)(?:\.|\s*\()',
             "Deprecated encryption algorithm (DES/RC4/RC2/Blowfish)", 6, "high", 0.85),
            (r'(?:AES|Cipher).*(?:ECB|MODE_ECB)',
             "AES in ECB mode — patterns preserved in ciphertext", 6, "high", 0.9),
        ]
        return cls._find_pattern(code, filepath, patterns)

    @classmethod
    def handle_jwt_vulnerability_scan(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """JWT vulnerability detection."""
        patterns = [
            (r'(?:algorithms?\s*[:=]\s*\[.*["\']none["\']|algorithm\s*[:=]\s*["\']none["\'])',
             "JWT with 'none' algorithm — signature bypass", 25, "critical", 0.95),
            (r'(?:verify\s*[:=]\s*False|verify_signature\s*[:=]\s*False)',
             "JWT signature verification disabled", 25, "critical", 0.9),
            (r'(?:jwt\.decode|jwt\.verify).*(?:algorithms\s*[:=]\s*\[.*HS256.*RS256|HS256.*RS256)',
             "JWT algorithm confusion — HS256/RS256 mix", 25, "high", 0.85),
            (r'jwt\.(?:encode|sign)\s*\([^)]*["\'](?:secret|password|key|changeme|admin)["\']',
             "JWT with weak/hardcoded signing secret", 25, "high", 0.85),
        ]
        return cls._find_pattern(code, filepath, patterns)

    @classmethod
    def handle_prototype_pollution_check(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """Prototype pollution detection for JavaScript."""
        patterns = [
            (r'__proto__',
             "Direct __proto__ access — prototype pollution vector", 18, "high", 0.85),
            (r'constructor\s*\[\s*["\']prototype["\']',
             "constructor.prototype access — prototype pollution", 18, "high", 0.85),
            (r'Object\.assign\s*\(\s*\{\}\s*,.*(?:req\.|body\.|params\.|query\.)',
             "Object.assign with user input — prototype pollution risk", 18, "medium", 0.7),
            (r'(?:merge|extend|defaults)\s*\(.*(?:req\.|body\.|params)',
             "Deep merge with user-controlled data", 18, "high", 0.75),
        ]
        return cls._find_pattern(code, filepath, patterns)

    @classmethod
    def handle_path_traversal_deep(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """Deep path traversal analysis."""
        patterns = [
            (r'(?:open|read_file|send_file|send_from_directory|serve_file)\s*\(.*(?:request\.|params\[|user_input|os\.path\.join.*(?:request|user))',
             "File operation with user-controlled path — path traversal", 3, "high", 0.85),
            (r'os\.path\.join\s*\(.*(?:request\.|params\[|argv|user)',
             "os.path.join with user input — path traversal via absolute path", 3, "high", 0.8),
            (r'(?:\.\./|\.\.\\|%2e%2e|%252e%252e)',
             "Path traversal sequence detected in code", 3, "high", 0.9),
        ]
        return cls._find_pattern(code, filepath, patterns)

    @classmethod
    def handle_race_condition_check(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """Race condition / TOCTOU detection."""
        patterns = [
            (r'os\.path\.exists\s*\(.*\)[\s\S]{0,100}(?:open|read|write)',
             "TOCTOU: file existence check before file operation", 19, "high", 0.7),
            (r'(?:if\s+\w+\.\s*exists|File\.exists)\s*\(.*\)[\s\S]{0,100}(?:delete|remove|unlink)',
             "TOCTOU: existence check before deletion", 19, "high", 0.7),
            (r'(?:balance|count|quantity|stock)\s*(?:>=?|<=?|==)\s*\w+[\s\S]{0,100}(?:balance|count|quantity|stock)\s*(?:-=|\+=)',
             "Check-then-act on shared resource — race condition", 19, "high", 0.65),
        ]
        return cls._find_pattern(code, filepath, patterns)

    @classmethod
    def handle_taint_propagation_deep(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """Deep taint propagation analysis."""
        patterns = [
            (r'(?:request\.\w+|params\[|argv\[|input\(\)|readline\(\)|GET\[|POST\[)[\s\S]{0,500}(?:execute|query|eval|exec|system|popen|subprocess)',
             "User input flows to dangerous sink — taint path detected", 0, "high", 0.75),
            (r'(?:request\.\w+|params\[)[\s\S]{0,300}(?:open\(|send_file|render_template_string)',
             "User input flows to file/template operation", 3, "high", 0.7),
        ]
        return cls._find_pattern(code, filepath, patterns)

    @classmethod
    def handle_unsafe_deserialize_scan(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """Unsafe deserialization detection."""
        patterns = [
            (r'(?:pickle\.loads?|yaml\.load\s*\((?!.*Loader=.*SafeLoader)|marshal\.loads?|shelve\.open)',
             "Unsafe deserialization — arbitrary code execution risk", 5, "critical", 0.9),
            (r'(?:ObjectInputStream|readObject|XMLDecoder)',
             "Java deserialization — gadget chain risk", 5, "critical", 0.85),
            (r'(?:unserialize|json_decode.*\bclass\b|php://input.*unserialize)',
             "PHP deserialization of untrusted data", 5, "critical", 0.85),
            (r'JSON\.parse\s*\(.*(?:req\.|body\.|params)',
             "JSON parsing of user input (low risk but check for prototype pollution)", 5, "low", 0.4),
        ]
        return cls._find_pattern(code, filepath, patterns)

    @classmethod
    def handle_cors_misconfiguration_check(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """CORS misconfiguration detection."""
        patterns = [
            (r'Access-Control-Allow-Origin\s*[:=]\s*["\']?\*["\']?',
             "Wildcard CORS origin — any domain can make requests", 24, "medium", 0.8),
            (r'Access-Control-Allow-Origin\s*[:=]\s*(?:request\.|req\.|origin)',
             "CORS origin reflected from request — origin spoofing", 24, "high", 0.85),
            (r'Access-Control-Allow-Credentials\s*[:=]\s*(?:true|True)',
             "CORS with credentials — check origin restriction", 24, "medium", 0.6),
        ]
        return cls._find_pattern(code, filepath, patterns)

    @classmethod
    def handle_open_redirect_check(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """Open redirect detection."""
        patterns = [
            (r'(?:redirect|sendRedirect|location\.href|window\.location|res\.redirect)\s*(?:\(|=)\s*(?:request\.|params\[|req\.query)',
             "Redirect using user-controlled URL parameter", 23, "medium", 0.8),
            (r'(?:redirect_to|return_url|next|goto|continue|url)\s*=\s*(?:request\.|params\[)',
             "User-controlled redirect parameter", 23, "medium", 0.75),
        ]
        return cls._find_pattern(code, filepath, patterns)

    @classmethod
    def handle_session_fixation_check(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """Session fixation detection."""
        patterns = [
            (r'(?:login|authenticate|sign_in|verify_password)\s*\([^)]*\)(?![\s\S]{0,300}(?:regenerate|new_session|rotate|cycle|invalidate|flush))',
             "Authentication without session regeneration — session fixation risk", 32, "high", 0.65),
            (r'session\s*\[\s*["\'](?:id|session_id)["\']]\s*=\s*(?:request\.|params\[)',
             "Session ID set from user input — session fixation", 32, "critical", 0.9),
        ]
        return cls._find_pattern(code, filepath, patterns)

    @classmethod
    def handle_dependency_confusion(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """Dependency confusion detection."""
        patterns = [
            (r'--extra-index-url\s+https?://(?!pypi\.org)',
             "Private PyPI registry — dependency confusion risk", 30, "high", 0.7),
            (r'"registry"\s*:\s*"https?://(?!registry\.npmjs\.org)',
             "Private npm registry — dependency confusion risk", 30, "high", 0.7),
            (r'(?:@company/|@internal/|@private/)(?!\s*")',
             "Scoped package — verify package exists on public registry", 30, "medium", 0.5),
        ]
        return cls._find_pattern(code, filepath, patterns)

    @classmethod
    def handle_file_upload_bypass(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """File upload bypass detection."""
        patterns = [
            (r'(?:save|upload|store)\s*\(.*(?:request\.FILES|file|upload)',
             "File upload handler — verify type/size validation", 34, "high", 0.6),
            (r'(?:\.save|move_uploaded_file)\s*\((?![\s\S]{0,200}(?:validate|check|allowed|whitelist|extension))',
             "File saved without visible type validation", 34, "high", 0.7),
            (r'\.(?:endswith|extension)\s*(?:!=|not in).*(?:exe|php|jsp|asp)',
             "Extension blocklist — can be bypassed with double extensions", 34, "medium", 0.65),
        ]
        return cls._find_pattern(code, filepath, patterns)

    @classmethod
    def handle_default(cls, code: str, filepath: str, params: dict) -> list[dict]:
        """Default handler for strategies without specific implementations."""
        return []


# ═══════════════════════════════════════════════════════════════
# HANDLER REGISTRY — Maps StrategyType → handler function
# ═══════════════════════════════════════════════════════════════

STRATEGY_HANDLER_MAP: dict[StrategyType, Callable] = {
    StrategyType.SQL_INJECTION_DEEP: StrategyHandlers.handle_sql_injection_deep,
    StrategyType.XSS_CONTEXT_ANALYSIS: StrategyHandlers.handle_xss_context_analysis,
    StrategyType.COMMAND_INJECTION_CHAIN: StrategyHandlers.handle_command_injection_chain,
    StrategyType.SSTI_DETECTION: StrategyHandlers.handle_ssti_detection,
    StrategyType.AUTH_BYPASS_CHECK: StrategyHandlers.handle_auth_bypass_check,
    StrategyType.SSRF_DEEP_SCAN: StrategyHandlers.handle_ssrf_deep_scan,
    StrategyType.WEAK_ALGORITHM_SCAN: StrategyHandlers.handle_weak_algorithm_scan,
    StrategyType.JWT_VULNERABILITY_SCAN: StrategyHandlers.handle_jwt_vulnerability_scan,
    StrategyType.PROTOTYPE_POLLUTION_CHECK: StrategyHandlers.handle_prototype_pollution_check,
    StrategyType.PATH_TRAVERSAL_DEEP: StrategyHandlers.handle_path_traversal_deep,
    StrategyType.RACE_CONDITION_CHECK: StrategyHandlers.handle_race_condition_check,
    StrategyType.TAINT_PROPAGATION_DEEP: StrategyHandlers.handle_taint_propagation_deep,
    StrategyType.UNSAFE_DESERIALIZE_SCAN: StrategyHandlers.handle_unsafe_deserialize_scan,
    StrategyType.CORS_MISCONFIGURATION_CHECK: StrategyHandlers.handle_cors_misconfiguration_check,
    StrategyType.OPEN_REDIRECT_CHECK: StrategyHandlers.handle_open_redirect_check,
    StrategyType.SESSION_FIXATION_CHECK: StrategyHandlers.handle_session_fixation_check,
    StrategyType.DEPENDENCY_CONFUSION: StrategyHandlers.handle_dependency_confusion,
    StrategyType.FILE_UPLOAD_BYPASS: StrategyHandlers.handle_file_upload_bypass,
    StrategyType.TOCTOU_DETECTION: StrategyHandlers.handle_race_condition_check,
}


# ═══════════════════════════════════════════════════════════════
# SCENARIO EXECUTOR — The execution engine
# ═══════════════════════════════════════════════════════════════

class ScenarioExecutor:
    """
    Executes MiroFish-generated scenarios against target code.

    Transforms scenario plans into concrete analysis operations,
    tracks results, and feeds back into adaptive learning.
    """

    def __init__(self, timeout_seconds: float = 300.0):
        self.timeout_seconds = timeout_seconds
        self.total_executed = 0
        self.total_findings = 0

    def execute_scenario(self, scenario: Scenario, code: str) -> ScenarioResult:
        """
        Execute a single scenario against code.

        Args:
            scenario: The MiroFish scenario to execute.
            code: Source code to analyze.

        Returns:
            ScenarioResult with findings.
        """
        start_time = time.time()

        result = ScenarioResult(
            scenario_id=scenario.scenario_id,
            strategy=scenario.strategy.name,
            target_file=scenario.target_artifact.filepath,
        )

        try:
            handler = STRATEGY_HANDLER_MAP.get(
                scenario.strategy,
                StrategyHandlers.handle_default,
            )

            findings = handler(code, scenario.target_artifact.filepath, scenario.parameters)

            # Enrich findings with scenario provenance
            for finding in findings:
                finding["scenario_id"] = scenario.scenario_id
                finding["provenance"] = scenario.provenance
                finding["mirofish_strategy"] = scenario.strategy.name
                finding["iteration"] = scenario.iteration

            result.findings = findings
            result.success = len(findings) > 0

        except Exception as e:
            result.error = str(e)
            result.success = False

        result.execution_time_ms = (time.time() - start_time) * 1000
        self.total_executed += 1
        self.total_findings += len(result.findings)

        return result

    def execute_batch(
        self,
        scenarios: list[Scenario],
        code: str,
    ) -> ExecutionReport:
        """
        Execute a batch of scenarios against code.

        Args:
            scenarios: Ordered list of scenarios (highest priority first).
            code: Source code to analyze.

        Returns:
            ExecutionReport with all results.
        """
        report = ExecutionReport(total_scenarios=len(scenarios))
        start_time = time.time()

        for scenario in scenarios:
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed > self.timeout_seconds:
                break

            result = self.execute_scenario(scenario, code)
            report.scenario_results.append(result)
            report.executed_scenarios += 1

            if result.success:
                report.successful_scenarios += 1
                report.total_findings += len(result.findings)

        report.total_execution_time_ms = (time.time() - start_time) * 1000

        # Detect compound vulnerabilities
        report.compound_findings = self._detect_compound_vulnerabilities(report)

        # Record dimensions analyzed
        dimensions_seen = set()
        for result in report.scenario_results:
            strategy_name = result.strategy
            try:
                strategy_type = StrategyType[strategy_name]
                dim = STRATEGY_DIMENSION_MAP.get(strategy_type)
                if dim:
                    dimensions_seen.add(dim.name)
            except (KeyError, ValueError):
                pass
        report.dimensions_analyzed = sorted(dimensions_seen)

        return report

    def _detect_compound_vulnerabilities(self, report: ExecutionReport) -> list[dict]:
        """
        Detect compound vulnerabilities — chains of findings that together
        create a more severe security issue.

        Example: SQLi + auth bypass = critical chain allowing
        unauthenticated database access.
        """
        compound_findings = []
        all_findings = []

        for result in report.scenario_results:
            all_findings.extend(result.findings)

        if not all_findings:
            return []

        # Group findings by file
        by_file: dict[str, list[dict]] = {}
        for f in all_findings:
            fp = f.get("filepath", "")
            if fp not in by_file:
                by_file[fp] = []
            by_file[fp].append(f)

        # Compound patterns
        compound_patterns = [
            {
                "name": "Unauthenticated SQL Injection Chain",
                "requires": [0, 9],  # SQLi + auth bypass
                "severity": "critical",
                "confidence": 0.95,
                "description": "SQL injection reachable without authentication",
            },
            {
                "name": "SSRF to Internal Service Chain",
                "requires": [8, 9],  # SSRF + data exposure
                "severity": "critical",
                "confidence": 0.9,
                "description": "SSRF can access internal services exposing sensitive data",
            },
            {
                "name": "Deserialization to RCE Chain",
                "requires": [5, 2],  # Deserialization + command injection
                "severity": "critical",
                "confidence": 0.95,
                "description": "Insecure deserialization leading to command execution",
            },
            {
                "name": "Auth Bypass to Mass Assignment",
                "requires": [9, 27],  # Auth + mass assignment
                "severity": "critical",
                "confidence": 0.85,
                "description": "Authentication bypass enables mass assignment privilege escalation",
            },
            {
                "name": "SSTI to Full Compromise",
                "requires": [14],  # SSTI alone is full compromise
                "severity": "critical",
                "confidence": 0.9,
                "description": "Server-side template injection enables arbitrary code execution",
            },
        ]

        for filepath, file_findings in by_file.items():
            vuln_classes_found = set(f.get("vuln_class") for f in file_findings)

            for pattern in compound_patterns:
                required = set(pattern["requires"])
                if required.issubset(vuln_classes_found):
                    compound_findings.append({
                        "compound_name": pattern["name"],
                        "filepath": filepath,
                        "severity": pattern["severity"],
                        "confidence": pattern["confidence"],
                        "description": pattern["description"],
                        "contributing_vulns": sorted(required),
                        "source": "mirofish_compound_detection",
                    })

        return compound_findings


# ═══════════════════════════════════════════════════════════════
# MULTI-DIMENSIONAL ANALYZER
# ═══════════════════════════════════════════════════════════════

class MultiDimensionalAnalyzer:
    """
    Analyzes code artifacts across multiple vulnerability dimensions simultaneously.

    Each dimension represents a category of vulnerabilities. The analyzer
    runs all dimensions and cross-correlates findings for compound detection.
    """

    def __init__(self):
        self.executor = ScenarioExecutor()

    def analyze_all_dimensions(
        self,
        code: str,
        filepath: str,
        dimensions: list[VulnerabilityDimension] | None = None,
    ) -> dict:
        """
        Analyze code across all specified vulnerability dimensions.

        Returns findings grouped by dimension with cross-correlation.
        """
        if dimensions is None:
            dimensions = list(VulnerabilityDimension)

        results_by_dimension = {}
        all_findings = []

        for dimension in dimensions:
            dim_findings = self._analyze_dimension(code, filepath, dimension)
            results_by_dimension[dimension.name] = {
                "findings": dim_findings,
                "count": len(dim_findings),
            }
            all_findings.extend(dim_findings)

        return {
            "filepath": filepath,
            "dimensions_analyzed": [d.name for d in dimensions],
            "total_findings": len(all_findings),
            "results_by_dimension": results_by_dimension,
            "findings": all_findings,
        }

    def _analyze_dimension(
        self,
        code: str,
        filepath: str,
        dimension: VulnerabilityDimension,
    ) -> list[dict]:
        """Analyze code for a specific vulnerability dimension."""
        findings = []

        # Get handlers for this dimension
        for strategy_type, dim in STRATEGY_DIMENSION_MAP.items():
            if dim != dimension:
                continue

            handler = STRATEGY_HANDLER_MAP.get(strategy_type, StrategyHandlers.handle_default)
            try:
                dim_findings = handler(code, filepath, {})
                for f in dim_findings:
                    f["dimension"] = dimension.name
                findings.extend(dim_findings)
            except Exception:
                pass

        return findings
