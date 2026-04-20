"""
BAYREUTHWING — MiroFish Scenario Engine

The autonomous analysis brain. Generates exhaustive, deterministic attack and
analysis scenarios from discovered artifacts. Designed to behave like a
persistent security researcher that never stops until every code path,
every hidden surface, and every potential vulnerability has been explored.

Anti-Hallucination Safeguards:
    - All strategy types are enum-bounded (StrategyType)
    - No LLM/generative content — purely rule-based
    - Every scenario carries provenance (source artifact + generating rule)
    - Iteration cap prevents infinite loops
    - All outputs are traceable and auditable

Architecture:
    Artifacts (from reversing modules)
        → MiroFishEngine.generate_scenarios()
        → Deterministic strategy mapping
        → Priority scoring (with adaptive learning boost)
        → Scenario list (ordered, bounded, traceable)
"""

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


# ═══════════════════════════════════════════════════════════════
# ENUMS — All possible types. Nothing can be invented at runtime.
# ═══════════════════════════════════════════════════════════════

class ArtifactType(Enum):
    """Every kind of artifact the reversing modules can discover."""
    BINARY_BEHAVIOR = auto()
    EMBEDDED_SECRET = auto()
    API_ENDPOINT = auto()
    API_PATTERN = auto()
    HIDDEN_ROUTE = auto()
    LOGIC_PATH = auto()
    CONTROL_FLOW = auto()
    IMPORT_CHAIN = auto()
    CRYPTO_USAGE = auto()
    AUTH_MECHANISM = auto()
    SERIALIZATION_POINT = auto()
    FILE_OPERATION = auto()
    NETWORK_CALL = auto()
    DATA_SINK = auto()
    DATA_SOURCE = auto()
    OBFUSCATION_MARKER = auto()
    PACKER_SIGNATURE = auto()
    DEBUG_ARTIFACT = auto()
    ENVIRONMENT_GATE = auto()
    FEATURE_FLAG = auto()
    ERROR_HANDLER = auto()
    MIDDLEWARE = auto()
    WEBSOCKET_ENDPOINT = auto()
    GRAPHQL_SCHEMA = auto()
    GRPC_SERVICE = auto()
    CORS_CONFIG = auto()
    RATE_LIMIT_CONFIG = auto()
    SESSION_MANAGEMENT = auto()
    INPUT_VALIDATION = auto()
    OUTPUT_ENCODING = auto()


class StrategyType(Enum):
    """Every analysis strategy MiroFish can generate. Finite. Auditable."""
    # Binary analysis
    ENTROPY_SCAN = auto()
    STRING_EXTRACTION_DEEP = auto()
    HEADER_ANALYSIS = auto()
    PACKER_DETECTION = auto()
    IMPORT_TABLE_SCAN = auto()
    SECTION_ANALYSIS = auto()
    SIGNATURE_MATCH = auto()
    EMBEDDED_RESOURCE_SCAN = auto()

    # Endpoint / API analysis
    AUTH_BYPASS_CHECK = auto()
    PARAMETER_INJECTION_PROBE = auto()
    METHOD_ENUMERATION = auto()
    VERB_TAMPERING_CHECK = auto()
    RATE_LIMIT_PROBE = auto()
    SCOPE_ESCALATION_CHECK = auto()
    CORS_MISCONFIGURATION_CHECK = auto()
    CONTENT_TYPE_CONFUSION = auto()
    PATH_PARAMETER_TRAVERSAL = auto()
    MASS_ASSIGNMENT_CHECK = auto()
    IDOR_PATTERN_CHECK = auto()
    BOLA_PATTERN_CHECK = auto()

    # Injection analysis
    SQL_INJECTION_DEEP = auto()
    XSS_CONTEXT_ANALYSIS = auto()
    COMMAND_INJECTION_CHAIN = auto()
    SSTI_DETECTION = auto()
    LDAP_INJECTION_CHECK = auto()
    XPATH_INJECTION_CHECK = auto()
    HEADER_INJECTION_CHECK = auto()
    CRLF_INJECTION_CHECK = auto()
    LOG_INJECTION_CHECK = auto()

    # Crypto analysis
    WEAK_ALGORITHM_SCAN = auto()
    KEY_MANAGEMENT_AUDIT = auto()
    IV_REUSE_DETECTION = auto()
    PADDING_ORACLE_CHECK = auto()
    HASH_WITHOUT_SALT = auto()
    INSECURE_RANDOM_CHECK = auto()
    CERTIFICATE_VALIDATION_CHECK = auto()
    TLS_CONFIGURATION_AUDIT = auto()

    # Auth / Session
    SESSION_FIXATION_CHECK = auto()
    TOKEN_ENTROPY_CHECK = auto()
    COOKIE_SECURITY_AUDIT = auto()
    PASSWORD_STORAGE_AUDIT = auto()
    PRIVILEGE_ESCALATION_PATH = auto()
    BROKEN_AUTH_FLOW = auto()
    JWT_VULNERABILITY_SCAN = auto()
    OAUTH_MISCONFIGURATION = auto()

    # Deserialization
    UNSAFE_DESERIALIZE_SCAN = auto()
    GADGET_CHAIN_DETECTION = auto()
    TYPE_CONFUSION_CHECK = auto()
    PROTOTYPE_POLLUTION_CHECK = auto()

    # Logic / Flow
    BRANCH_COVERAGE_ANALYSIS = auto()
    DEAD_CODE_DETECTION = auto()
    EXCEPTION_PATH_ANALYSIS = auto()
    RACE_CONDITION_CHECK = auto()
    TOCTOU_DETECTION = auto()
    BUSINESS_LOGIC_BYPASS = auto()
    INTEGER_OVERFLOW_CHECK = auto()
    NULL_DEREFERENCE_SCAN = auto()
    RESOURCE_LEAK_DETECTION = auto()
    INFINITE_LOOP_DETECTION = auto()
    RECURSION_DEPTH_CHECK = auto()

    # Data flow
    TAINT_PROPAGATION_DEEP = auto()
    SENSITIVE_DATA_FLOW = auto()
    PII_EXPOSURE_CHECK = auto()
    LOGGING_SECRETS_CHECK = auto()
    ERROR_INFO_LEAK = auto()
    STACK_TRACE_EXPOSURE = auto()

    # File / Resource
    PATH_TRAVERSAL_DEEP = auto()
    FILE_INCLUSION_CHECK = auto()
    TEMP_FILE_RACE = auto()
    SYMLINK_ATTACK_CHECK = auto()
    FILE_UPLOAD_BYPASS = auto()

    # Network / SSRF
    SSRF_DEEP_SCAN = auto()
    DNS_REBINDING_CHECK = auto()
    OPEN_REDIRECT_CHECK = auto()
    WEBHOOK_INJECTION_CHECK = auto()

    # Supply chain
    DEPENDENCY_CONFUSION = auto()
    TYPOSQUATTING_CHECK = auto()
    MALICIOUS_PACKAGE_SCAN = auto()

    # Obfuscation
    DEOBFUSCATION_ATTEMPT = auto()
    CONTROL_FLOW_FLATTEN_DETECT = auto()
    STRING_ENCRYPTION_DETECT = auto()
    ANTI_ANALYSIS_DETECT = auto()

    # Re-analysis with mutations
    MUTATED_RETRY = auto()
    CROSS_MODULE_CORRELATION = auto()
    DEEP_RECURSIVE_SCAN = auto()


class FindingSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ═══════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════

@dataclass
class Artifact:
    """
    A discovered item from reverse engineering analysis.
    This is what gets fed INTO MiroFish.
    """
    artifact_type: ArtifactType
    source_module: str        # Which module discovered this
    filepath: str             # File it was found in
    line: int = 0             # Line number (0 if N/A)
    content: str = ""         # The actual content / matched text
    metadata: dict = field(default_factory=dict)  # Extra context
    confidence: float = 0.5   # How confident the discovery is
    timestamp: float = field(default_factory=time.time)

    @property
    def hash_id(self) -> str:
        """Unique identity for deduplication."""
        raw = f"{self.artifact_type.name}:{self.source_module}:{self.filepath}:{self.line}:{self.content[:100]}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class Scenario:
    """
    A planned analysis strategy generated by MiroFish.
    This is what gets EXECUTED by the feedback loop.
    """
    strategy: StrategyType
    target_artifact: Artifact
    parameters: dict = field(default_factory=dict)
    priority: float = 0.5     # 0.0 = low, 1.0 = highest
    provenance: str = ""      # Rule that generated this scenario
    iteration: int = 0        # Which feedback loop iteration
    parent_scenario_id: str = ""  # If this is a mutation of another

    @property
    def scenario_id(self) -> str:
        raw = f"{self.strategy.name}:{self.target_artifact.hash_id}:{self.provenance}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "strategy": self.strategy.name,
            "target_artifact_type": self.target_artifact.artifact_type.name,
            "target_file": self.target_artifact.filepath,
            "priority": round(self.priority, 3),
            "provenance": self.provenance,
            "iteration": self.iteration,
            "parameters": self.parameters,
        }


# ═══════════════════════════════════════════════════════════════
# MIROFISH ENGINE
# ═══════════════════════════════════════════════════════════════

class MiroFishEngine:
    """
    The scenario generation brain of BayreuthWing.

    Given a set of discovered artifacts, generates an exhaustive list of
    analysis scenarios — every possible angle to analyze the target.
    Thinks like a persistent attacker who never gives up.

    All outputs are deterministic and traceable. No hallucination possible
    because every strategy comes from the StrategyType enum and every
    scenario links back to its source artifact and generating rule.
    """

    # Maximum scenarios per artifact (prevents explosion)
    MAX_SCENARIOS_PER_ARTIFACT = 25
    # Maximum total scenarios per iteration
    MAX_SCENARIOS_PER_ITERATION = 200
    # Default max feedback loop iterations
    DEFAULT_MAX_ITERATIONS = 10

    def __init__(self, max_iterations: int = DEFAULT_MAX_ITERATIONS):
        self.max_iterations = max_iterations
        self._strategy_map = self._build_strategy_map()

    def _build_strategy_map(self) -> dict[ArtifactType, list[tuple[StrategyType, float, str, dict]]]:
        """
        Master mapping: artifact type → list of (strategy, base_priority, provenance_rule, params).

        This is the complete brain. Every possible analysis path is defined here.
        Nothing is generated dynamically. Everything is auditable.
        """
        return {
            # ── Binary artifacts ─────────────────────────────
            ArtifactType.BINARY_BEHAVIOR: [
                (StrategyType.ENTROPY_SCAN, 0.9, "MIRO-BIN-001: High entropy regions suggest encryption/packing", {}),
                (StrategyType.STRING_EXTRACTION_DEEP, 0.85, "MIRO-BIN-002: Deep string extraction for secrets", {"min_length": 6, "include_unicode": True}),
                (StrategyType.HEADER_ANALYSIS, 0.8, "MIRO-BIN-003: PE/ELF header analysis for anomalies", {}),
                (StrategyType.PACKER_DETECTION, 0.9, "MIRO-BIN-004: Known packer signature matching", {}),
                (StrategyType.IMPORT_TABLE_SCAN, 0.75, "MIRO-BIN-005: Import table for dangerous API usage", {}),
                (StrategyType.SECTION_ANALYSIS, 0.7, "MIRO-BIN-006: Section permissions and sizes", {}),
                (StrategyType.SIGNATURE_MATCH, 0.85, "MIRO-BIN-007: Known malware/tool signatures", {}),
                (StrategyType.EMBEDDED_RESOURCE_SCAN, 0.8, "MIRO-BIN-008: Embedded resources may contain config/keys", {}),
                (StrategyType.DEOBFUSCATION_ATTEMPT, 0.7, "MIRO-BIN-009: Attempt to deobfuscate identified patterns", {}),
                (StrategyType.ANTI_ANALYSIS_DETECT, 0.65, "MIRO-BIN-010: Detect anti-debugging/anti-analysis tricks", {}),
            ],

            ArtifactType.EMBEDDED_SECRET: [
                (StrategyType.STRING_EXTRACTION_DEEP, 0.95, "MIRO-SEC-001: Deep extraction around secret location", {"context_bytes": 4096}),
                (StrategyType.SENSITIVE_DATA_FLOW, 0.9, "MIRO-SEC-002: Trace where the secret flows", {}),
                (StrategyType.LOGGING_SECRETS_CHECK, 0.85, "MIRO-SEC-003: Check if secret appears in logs", {}),
                (StrategyType.KEY_MANAGEMENT_AUDIT, 0.9, "MIRO-SEC-004: Audit key storage and rotation", {}),
                (StrategyType.PII_EXPOSURE_CHECK, 0.8, "MIRO-SEC-005: Check for PII near secret", {}),
                (StrategyType.ERROR_INFO_LEAK, 0.75, "MIRO-SEC-006: Check if secret leaks in error responses", {}),
            ],

            # ── Endpoint artifacts ───────────────────────────
            ArtifactType.API_ENDPOINT: [
                (StrategyType.AUTH_BYPASS_CHECK, 0.95, "MIRO-EP-001: Check if endpoint can be accessed without auth", {}),
                (StrategyType.PARAMETER_INJECTION_PROBE, 0.9, "MIRO-EP-002: Test all parameters for injection", {}),
                (StrategyType.METHOD_ENUMERATION, 0.85, "MIRO-EP-003: Try all HTTP methods", {}),
                (StrategyType.VERB_TAMPERING_CHECK, 0.8, "MIRO-EP-004: Verb tampering bypass", {}),
                (StrategyType.IDOR_PATTERN_CHECK, 0.9, "MIRO-EP-005: Insecure direct object reference patterns", {}),
                (StrategyType.BOLA_PATTERN_CHECK, 0.9, "MIRO-EP-006: Broken object level authorization", {}),
                (StrategyType.MASS_ASSIGNMENT_CHECK, 0.85, "MIRO-EP-007: Mass assignment/over-posting", {}),
                (StrategyType.PATH_PARAMETER_TRAVERSAL, 0.85, "MIRO-EP-008: Path parameters for traversal", {}),
                (StrategyType.CONTENT_TYPE_CONFUSION, 0.7, "MIRO-EP-009: Content-type mismatch attacks", {}),
                (StrategyType.RATE_LIMIT_PROBE, 0.6, "MIRO-EP-010: Rate limiting presence", {}),
                (StrategyType.CORS_MISCONFIGURATION_CHECK, 0.8, "MIRO-EP-011: CORS policy validation", {}),
                (StrategyType.SQL_INJECTION_DEEP, 0.95, "MIRO-EP-012: Deep SQLi on endpoint parameters", {}),
                (StrategyType.XSS_CONTEXT_ANALYSIS, 0.9, "MIRO-EP-013: XSS by response context", {}),
                (StrategyType.COMMAND_INJECTION_CHAIN, 0.85, "MIRO-EP-014: Command injection through parameters", {}),
                (StrategyType.SSTI_DETECTION, 0.8, "MIRO-EP-015: Server-side template injection", {}),
                (StrategyType.OPEN_REDIRECT_CHECK, 0.75, "MIRO-EP-016: Open redirect via parameters", {}),
                (StrategyType.SSRF_DEEP_SCAN, 0.85, "MIRO-EP-017: SSRF through URL parameters", {}),
                (StrategyType.FILE_UPLOAD_BYPASS, 0.8, "MIRO-EP-018: File upload filter bypass", {}),
            ],

            ArtifactType.API_PATTERN: [
                (StrategyType.AUTH_BYPASS_CHECK, 0.9, "MIRO-API-001: Auth scheme bypass analysis", {}),
                (StrategyType.SCOPE_ESCALATION_CHECK, 0.85, "MIRO-API-002: API scope / permission escalation", {}),
                (StrategyType.VERB_TAMPERING_CHECK, 0.8, "MIRO-API-003: REST verb tampering", {}),
                (StrategyType.JWT_VULNERABILITY_SCAN, 0.9, "MIRO-API-004: JWT none/weak algorithm", {}),
                (StrategyType.OAUTH_MISCONFIGURATION, 0.85, "MIRO-API-005: OAuth flow misconfig", {}),
                (StrategyType.MASS_ASSIGNMENT_CHECK, 0.8, "MIRO-API-006: Mass assignment on API objects", {}),
                (StrategyType.BROKEN_AUTH_FLOW, 0.85, "MIRO-API-007: Broken authentication flow", {}),
                (StrategyType.PRIVILEGE_ESCALATION_PATH, 0.9, "MIRO-API-008: Privilege escalation paths", {}),
                (StrategyType.CROSS_MODULE_CORRELATION, 0.7, "MIRO-API-009: Cross-reference with other modules", {}),
            ],

            # ── Hidden routes ────────────────────────────────
            ArtifactType.HIDDEN_ROUTE: [
                (StrategyType.AUTH_BYPASS_CHECK, 0.95, "MIRO-HR-001: Hidden route often lacks auth", {}),
                (StrategyType.PARAMETER_INJECTION_PROBE, 0.9, "MIRO-HR-002: Hidden routes may skip input validation", {}),
                (StrategyType.BUSINESS_LOGIC_BYPASS, 0.9, "MIRO-HR-003: Hidden route may bypass business logic", {}),
                (StrategyType.PRIVILEGE_ESCALATION_PATH, 0.9, "MIRO-HR-004: Hidden admin/debug escalation", {}),
                (StrategyType.ERROR_INFO_LEAK, 0.85, "MIRO-HR-005: Debug routes leak info", {}),
                (StrategyType.STACK_TRACE_EXPOSURE, 0.85, "MIRO-HR-006: Debug routes expose stack traces", {}),
                (StrategyType.DEEP_RECURSIVE_SCAN, 0.8, "MIRO-HR-007: Recursively scan hidden route logic", {}),
            ],

            # ── Logic paths ─────────────────────────────────
            ArtifactType.LOGIC_PATH: [
                (StrategyType.BRANCH_COVERAGE_ANALYSIS, 0.85, "MIRO-LP-001: Explore all branches", {}),
                (StrategyType.DEAD_CODE_DETECTION, 0.7, "MIRO-LP-002: Dead code may contain old vulns", {}),
                (StrategyType.EXCEPTION_PATH_ANALYSIS, 0.9, "MIRO-LP-003: Exception handlers often have vulns", {}),
                (StrategyType.RACE_CONDITION_CHECK, 0.8, "MIRO-LP-004: Time-of-check-time-of-use", {}),
                (StrategyType.TOCTOU_DETECTION, 0.8, "MIRO-LP-005: TOCTOU in file/resource access", {}),
                (StrategyType.BUSINESS_LOGIC_BYPASS, 0.85, "MIRO-LP-006: Logic bypass through alternate paths", {}),
                (StrategyType.INTEGER_OVERFLOW_CHECK, 0.75, "MIRO-LP-007: Integer overflow in calculations", {}),
                (StrategyType.NULL_DEREFERENCE_SCAN, 0.7, "MIRO-LP-008: Null/undefined dereference", {}),
                (StrategyType.INFINITE_LOOP_DETECTION, 0.6, "MIRO-LP-009: Infinite loop / DoS potential", {}),
                (StrategyType.RECURSION_DEPTH_CHECK, 0.65, "MIRO-LP-010: Unbounded recursion", {}),
                (StrategyType.RESOURCE_LEAK_DETECTION, 0.7, "MIRO-LP-011: Unclosed files/connections/handles", {}),
                (StrategyType.TAINT_PROPAGATION_DEEP, 0.9, "MIRO-LP-012: Deep taint analysis through logic", {}),
            ],

            ArtifactType.CONTROL_FLOW: [
                (StrategyType.BRANCH_COVERAGE_ANALYSIS, 0.85, "MIRO-CF-001: Control flow branch coverage", {}),
                (StrategyType.CONTROL_FLOW_FLATTEN_DETECT, 0.8, "MIRO-CF-002: Flattened control flow (obfuscation)", {}),
                (StrategyType.RACE_CONDITION_CHECK, 0.75, "MIRO-CF-003: Race conditions in async paths", {}),
                (StrategyType.DEAD_CODE_DETECTION, 0.7, "MIRO-CF-004: Unreachable code analysis", {}),
                (StrategyType.BUSINESS_LOGIC_BYPASS, 0.8, "MIRO-CF-005: Logic bypass via control flow", {}),
            ],

            # ── Crypto artifacts ─────────────────────────────
            ArtifactType.CRYPTO_USAGE: [
                (StrategyType.WEAK_ALGORITHM_SCAN, 0.95, "MIRO-CRY-001: Weak/deprecated algorithms", {}),
                (StrategyType.KEY_MANAGEMENT_AUDIT, 0.9, "MIRO-CRY-002: Key storage and rotation", {}),
                (StrategyType.IV_REUSE_DETECTION, 0.85, "MIRO-CRY-003: IV/nonce reuse", {}),
                (StrategyType.PADDING_ORACLE_CHECK, 0.8, "MIRO-CRY-004: Padding oracle patterns", {}),
                (StrategyType.HASH_WITHOUT_SALT, 0.9, "MIRO-CRY-005: Unsalted hashing", {}),
                (StrategyType.INSECURE_RANDOM_CHECK, 0.85, "MIRO-CRY-006: Insecure PRNG for crypto", {}),
                (StrategyType.CERTIFICATE_VALIDATION_CHECK, 0.8, "MIRO-CRY-007: Certificate validation bypass", {}),
                (StrategyType.TLS_CONFIGURATION_AUDIT, 0.75, "MIRO-CRY-008: TLS config weaknesses", {}),
            ],

            # ── Auth artifacts ───────────────────────────────
            ArtifactType.AUTH_MECHANISM: [
                (StrategyType.BROKEN_AUTH_FLOW, 0.95, "MIRO-AUTH-001: Broken authentication flow", {}),
                (StrategyType.SESSION_FIXATION_CHECK, 0.9, "MIRO-AUTH-002: Session fixation", {}),
                (StrategyType.TOKEN_ENTROPY_CHECK, 0.85, "MIRO-AUTH-003: Token entropy analysis", {}),
                (StrategyType.COOKIE_SECURITY_AUDIT, 0.85, "MIRO-AUTH-004: Cookie flags audit", {}),
                (StrategyType.PASSWORD_STORAGE_AUDIT, 0.9, "MIRO-AUTH-005: Password hashing audit", {}),
                (StrategyType.PRIVILEGE_ESCALATION_PATH, 0.9, "MIRO-AUTH-006: Privilege escalation", {}),
                (StrategyType.JWT_VULNERABILITY_SCAN, 0.9, "MIRO-AUTH-007: JWT vulnerabilities", {}),
                (StrategyType.OAUTH_MISCONFIGURATION, 0.85, "MIRO-AUTH-008: OAuth misconfiguration", {}),
            ],

            # ── Serialization ────────────────────────────────
            ArtifactType.SERIALIZATION_POINT: [
                (StrategyType.UNSAFE_DESERIALIZE_SCAN, 0.95, "MIRO-SER-001: Unsafe deserialization", {}),
                (StrategyType.GADGET_CHAIN_DETECTION, 0.9, "MIRO-SER-002: Deserialization gadget chains", {}),
                (StrategyType.TYPE_CONFUSION_CHECK, 0.85, "MIRO-SER-003: Type confusion attacks", {}),
                (StrategyType.PROTOTYPE_POLLUTION_CHECK, 0.9, "MIRO-SER-004: Prototype pollution (JS)", {}),
            ],

            # ── File operations ──────────────────────────────
            ArtifactType.FILE_OPERATION: [
                (StrategyType.PATH_TRAVERSAL_DEEP, 0.95, "MIRO-FILE-001: Path traversal analysis", {}),
                (StrategyType.FILE_INCLUSION_CHECK, 0.9, "MIRO-FILE-002: Local/remote file inclusion", {}),
                (StrategyType.TEMP_FILE_RACE, 0.8, "MIRO-FILE-003: Temp file race condition", {}),
                (StrategyType.SYMLINK_ATTACK_CHECK, 0.75, "MIRO-FILE-004: Symlink following attacks", {}),
                (StrategyType.FILE_UPLOAD_BYPASS, 0.85, "MIRO-FILE-005: File upload filter bypass", {}),
                (StrategyType.TOCTOU_DETECTION, 0.8, "MIRO-FILE-006: TOCTOU in file access", {}),
            ],

            # ── Network calls ────────────────────────────────
            ArtifactType.NETWORK_CALL: [
                (StrategyType.SSRF_DEEP_SCAN, 0.95, "MIRO-NET-001: SSRF through network calls", {}),
                (StrategyType.DNS_REBINDING_CHECK, 0.8, "MIRO-NET-002: DNS rebinding attacks", {}),
                (StrategyType.OPEN_REDIRECT_CHECK, 0.85, "MIRO-NET-003: Open redirect via URL params", {}),
                (StrategyType.WEBHOOK_INJECTION_CHECK, 0.8, "MIRO-NET-004: Webhook URL injection", {}),
                (StrategyType.CERTIFICATE_VALIDATION_CHECK, 0.85, "MIRO-NET-005: Certificate pinning bypass", {}),
                (StrategyType.TLS_CONFIGURATION_AUDIT, 0.75, "MIRO-NET-006: TLS verification disabled", {}),
            ],

            # ── Data flow ────────────────────────────────────
            ArtifactType.DATA_SINK: [
                (StrategyType.TAINT_PROPAGATION_DEEP, 0.95, "MIRO-SINK-001: Deep taint to this sink", {}),
                (StrategyType.SQL_INJECTION_DEEP, 0.9, "MIRO-SINK-002: SQLi at data sink", {}),
                (StrategyType.XSS_CONTEXT_ANALYSIS, 0.9, "MIRO-SINK-003: XSS at output sink", {}),
                (StrategyType.COMMAND_INJECTION_CHAIN, 0.85, "MIRO-SINK-004: Command injection at sink", {}),
                (StrategyType.LDAP_INJECTION_CHECK, 0.7, "MIRO-SINK-005: LDAP injection at sink", {}),
                (StrategyType.XPATH_INJECTION_CHECK, 0.7, "MIRO-SINK-006: XPath injection at sink", {}),
                (StrategyType.LOG_INJECTION_CHECK, 0.75, "MIRO-SINK-007: Log injection at sink", {}),
                (StrategyType.HEADER_INJECTION_CHECK, 0.8, "MIRO-SINK-008: Header injection at sink", {}),
                (StrategyType.CRLF_INJECTION_CHECK, 0.8, "MIRO-SINK-009: CRLF injection at sink", {}),
            ],

            ArtifactType.DATA_SOURCE: [
                (StrategyType.TAINT_PROPAGATION_DEEP, 0.9, "MIRO-SRC-001: Trace taint from this source", {}),
                (StrategyType.SENSITIVE_DATA_FLOW, 0.85, "MIRO-SRC-002: Sensitive data exposure from source", {}),
                (StrategyType.PII_EXPOSURE_CHECK, 0.8, "MIRO-SRC-003: PII leakage from source", {}),
                (StrategyType.INPUT_VALIDATION_DEEP, 0.9, "MIRO-SRC-004: Input validation at source", {"strategy_override": StrategyType.PARAMETER_INJECTION_PROBE}),
            ],

            # ── Obfuscation ──────────────────────────────────
            ArtifactType.OBFUSCATION_MARKER: [
                (StrategyType.DEOBFUSCATION_ATTEMPT, 0.9, "MIRO-OBF-001: Attempt deobfuscation", {}),
                (StrategyType.CONTROL_FLOW_FLATTEN_DETECT, 0.85, "MIRO-OBF-002: Control flow flattening", {}),
                (StrategyType.STRING_ENCRYPTION_DETECT, 0.85, "MIRO-OBF-003: Encrypted strings", {}),
                (StrategyType.ANTI_ANALYSIS_DETECT, 0.8, "MIRO-OBF-004: Anti-analysis techniques", {}),
                (StrategyType.DEEP_RECURSIVE_SCAN, 0.9, "MIRO-OBF-005: Deep scan after deobfuscation", {}),
            ],

            ArtifactType.PACKER_SIGNATURE: [
                (StrategyType.PACKER_DETECTION, 0.95, "MIRO-PACK-001: Identify packer type", {}),
                (StrategyType.ENTROPY_SCAN, 0.9, "MIRO-PACK-002: Entropy analysis of packed regions", {}),
                (StrategyType.EMBEDDED_RESOURCE_SCAN, 0.85, "MIRO-PACK-003: Resources hidden by packer", {}),
                (StrategyType.DEEP_RECURSIVE_SCAN, 0.9, "MIRO-PACK-004: Deep analysis after unpacking", {}),
            ],

            # ── Environment / Feature gates ──────────────────
            ArtifactType.ENVIRONMENT_GATE: [
                (StrategyType.BUSINESS_LOGIC_BYPASS, 0.9, "MIRO-ENV-001: Bypass environment gates", {}),
                (StrategyType.BRANCH_COVERAGE_ANALYSIS, 0.85, "MIRO-ENV-002: Explore both branches of gate", {}),
                (StrategyType.PRIVILEGE_ESCALATION_PATH, 0.8, "MIRO-ENV-003: Environment-gated privilege", {}),
                (StrategyType.AUTH_BYPASS_CHECK, 0.85, "MIRO-ENV-004: Auth bypass via env manipulation", {}),
            ],

            ArtifactType.FEATURE_FLAG: [
                (StrategyType.BUSINESS_LOGIC_BYPASS, 0.85, "MIRO-FF-001: Feature flag bypass", {}),
                (StrategyType.DEAD_CODE_DETECTION, 0.8, "MIRO-FF-002: Disabled features may have vulns", {}),
                (StrategyType.BRANCH_COVERAGE_ANALYSIS, 0.8, "MIRO-FF-003: Both sides of feature flag", {}),
            ],

            ArtifactType.DEBUG_ARTIFACT: [
                (StrategyType.ERROR_INFO_LEAK, 0.95, "MIRO-DBG-001: Debug info leakage", {}),
                (StrategyType.STACK_TRACE_EXPOSURE, 0.9, "MIRO-DBG-002: Stack trace exposure", {}),
                (StrategyType.AUTH_BYPASS_CHECK, 0.9, "MIRO-DBG-003: Debug mode auth bypass", {}),
                (StrategyType.PRIVILEGE_ESCALATION_PATH, 0.85, "MIRO-DBG-004: Debug privilege escalation", {}),
                (StrategyType.LOGGING_SECRETS_CHECK, 0.85, "MIRO-DBG-005: Debug logging exposes secrets", {}),
            ],

            # ── Error handling ───────────────────────────────
            ArtifactType.ERROR_HANDLER: [
                (StrategyType.ERROR_INFO_LEAK, 0.9, "MIRO-ERR-001: Error handler info leak", {}),
                (StrategyType.STACK_TRACE_EXPOSURE, 0.9, "MIRO-ERR-002: Stack trace in error response", {}),
                (StrategyType.EXCEPTION_PATH_ANALYSIS, 0.85, "MIRO-ERR-003: Exception path vulnerabilities", {}),
                (StrategyType.SENSITIVE_DATA_FLOW, 0.8, "MIRO-ERR-004: Sensitive data in error output", {}),
            ],

            # ── Middleware ───────────────────────────────────
            ArtifactType.MIDDLEWARE: [
                (StrategyType.AUTH_BYPASS_CHECK, 0.9, "MIRO-MW-001: Middleware bypass", {}),
                (StrategyType.CORS_MISCONFIGURATION_CHECK, 0.85, "MIRO-MW-002: CORS middleware misconfig", {}),
                (StrategyType.RATE_LIMIT_PROBE, 0.8, "MIRO-MW-003: Rate limit middleware bypass", {}),
                (StrategyType.CROSS_MODULE_CORRELATION, 0.75, "MIRO-MW-004: Middleware chain analysis", {}),
            ],

            # ── WebSocket ────────────────────────────────────
            ArtifactType.WEBSOCKET_ENDPOINT: [
                (StrategyType.AUTH_BYPASS_CHECK, 0.9, "MIRO-WS-001: WebSocket auth bypass", {}),
                (StrategyType.PARAMETER_INJECTION_PROBE, 0.85, "MIRO-WS-002: WebSocket message injection", {}),
                (StrategyType.CROSS_MODULE_CORRELATION, 0.8, "MIRO-WS-003: WS to HTTP correlation", {}),
                (StrategyType.RACE_CONDITION_CHECK, 0.8, "MIRO-WS-004: WebSocket race conditions", {}),
            ],

            # ── GraphQL ──────────────────────────────────────
            ArtifactType.GRAPHQL_SCHEMA: [
                (StrategyType.AUTH_BYPASS_CHECK, 0.95, "MIRO-GQL-001: GraphQL introspection/auth bypass", {}),
                (StrategyType.SQL_INJECTION_DEEP, 0.9, "MIRO-GQL-002: GraphQL resolver SQLi", {}),
                (StrategyType.IDOR_PATTERN_CHECK, 0.9, "MIRO-GQL-003: GraphQL IDOR/authorization", {}),
                (StrategyType.RECURSION_DEPTH_CHECK, 0.85, "MIRO-GQL-004: GraphQL depth/complexity DoS", {}),
                (StrategyType.SENSITIVE_DATA_FLOW, 0.85, "MIRO-GQL-005: GraphQL data exposure", {}),
            ],

            # ── gRPC ─────────────────────────────────────────
            ArtifactType.GRPC_SERVICE: [
                (StrategyType.AUTH_BYPASS_CHECK, 0.9, "MIRO-GRPC-001: gRPC auth bypass", {}),
                (StrategyType.PARAMETER_INJECTION_PROBE, 0.85, "MIRO-GRPC-002: gRPC message injection", {}),
                (StrategyType.TYPE_CONFUSION_CHECK, 0.8, "MIRO-GRPC-003: Protobuf type confusion", {}),
                (StrategyType.PRIVILEGE_ESCALATION_PATH, 0.8, "MIRO-GRPC-004: gRPC scope escalation", {}),
            ],

            # ── CORS / Rate Limit / Session / Input / Output ─
            ArtifactType.CORS_CONFIG: [
                (StrategyType.CORS_MISCONFIGURATION_CHECK, 0.95, "MIRO-CORS-001: CORS misconfiguration", {}),
                (StrategyType.AUTH_BYPASS_CHECK, 0.8, "MIRO-CORS-002: CORS + auth bypass", {}),
            ],
            ArtifactType.RATE_LIMIT_CONFIG: [
                (StrategyType.RATE_LIMIT_PROBE, 0.9, "MIRO-RL-001: Rate limit bypass", {}),
                (StrategyType.BUSINESS_LOGIC_BYPASS, 0.7, "MIRO-RL-002: Rate limit business logic", {}),
            ],
            ArtifactType.SESSION_MANAGEMENT: [
                (StrategyType.SESSION_FIXATION_CHECK, 0.9, "MIRO-SESS-001: Session fixation", {}),
                (StrategyType.COOKIE_SECURITY_AUDIT, 0.85, "MIRO-SESS-002: Cookie security flags", {}),
                (StrategyType.TOKEN_ENTROPY_CHECK, 0.85, "MIRO-SESS-003: Session token entropy", {}),
            ],
            ArtifactType.INPUT_VALIDATION: [
                (StrategyType.PARAMETER_INJECTION_PROBE, 0.9, "MIRO-IV-001: Input validation bypass", {}),
                (StrategyType.SQL_INJECTION_DEEP, 0.9, "MIRO-IV-002: SQLi through weak validation", {}),
                (StrategyType.XSS_CONTEXT_ANALYSIS, 0.9, "MIRO-IV-003: XSS through weak validation", {}),
                (StrategyType.COMMAND_INJECTION_CHAIN, 0.85, "MIRO-IV-004: Command injection through validation", {}),
            ],
            ArtifactType.OUTPUT_ENCODING: [
                (StrategyType.XSS_CONTEXT_ANALYSIS, 0.95, "MIRO-OE-001: XSS via encoding bypass", {}),
                (StrategyType.HEADER_INJECTION_CHECK, 0.8, "MIRO-OE-002: Header injection via encoding", {}),
                (StrategyType.CRLF_INJECTION_CHECK, 0.8, "MIRO-OE-003: CRLF via encoding bypass", {}),
            ],

            # ── Import chain ─────────────────────────────────
            ArtifactType.IMPORT_CHAIN: [
                (StrategyType.DEPENDENCY_CONFUSION, 0.85, "MIRO-IMP-001: Dependency confusion attack", {}),
                (StrategyType.TYPOSQUATTING_CHECK, 0.8, "MIRO-IMP-002: Typosquatting package names", {}),
                (StrategyType.MALICIOUS_PACKAGE_SCAN, 0.8, "MIRO-IMP-003: Known malicious packages", {}),
                (StrategyType.CROSS_MODULE_CORRELATION, 0.7, "MIRO-IMP-004: Cross-module correlation", {}),
            ],
        }

    def generate_scenarios(
        self,
        artifacts: list[Artifact],
        iteration: int = 0,
        seen_scenario_ids: set[str] | None = None,
    ) -> list[Scenario]:
        """
        Generate exhaustive analysis scenarios from discovered artifacts.

        Args:
            artifacts: Discovered artifacts from reversing modules.
            iteration: Current feedback loop iteration.
            seen_scenario_ids: Previously executed scenario IDs (for dedup).

        Returns:
            Ordered list of Scenario objects, highest priority first.
        """
        if seen_scenario_ids is None:
            seen_scenario_ids = set()

        scenarios = []

        for artifact in artifacts:
            strategies = self._strategy_map.get(artifact.artifact_type, [])

            for strategy_type, base_priority, provenance, params in strategies:
                # Handle strategy override (some entries map to a different strategy)
                actual_strategy = params.pop("strategy_override", None) or strategy_type
                if isinstance(actual_strategy, StrategyType):
                    strategy_type = actual_strategy

                scenario = Scenario(
                    strategy=strategy_type,
                    target_artifact=artifact,
                    parameters=dict(params),  # copy
                    priority=base_priority * artifact.confidence,
                    provenance=provenance,
                    iteration=iteration,
                )

                # Skip already-executed scenarios
                if scenario.scenario_id in seen_scenario_ids:
                    continue

                scenarios.append(scenario)

                # Cap per artifact
                artifact_scenarios = [s for s in scenarios if s.target_artifact.hash_id == artifact.hash_id]
                if len(artifact_scenarios) >= self.MAX_SCENARIOS_PER_ARTIFACT:
                    break

        # Sort by priority (highest first)
        scenarios.sort(key=lambda s: s.priority, reverse=True)

        # Cap total
        scenarios = scenarios[:self.MAX_SCENARIOS_PER_ITERATION]

        return scenarios

    # ═══════════════════════════════════════════════════════════
    # MULTI-DIMENSIONAL SCENARIO GENERATION
    # ═══════════════════════════════════════════════════════════

    # Vulnerability dimensions for multi-dimensional analysis
    VULNERABILITY_DIMENSIONS = {
        "injection": [
            StrategyType.SQL_INJECTION_DEEP, StrategyType.XSS_CONTEXT_ANALYSIS,
            StrategyType.COMMAND_INJECTION_CHAIN, StrategyType.SSTI_DETECTION,
            StrategyType.LDAP_INJECTION_CHECK, StrategyType.XPATH_INJECTION_CHECK,
            StrategyType.HEADER_INJECTION_CHECK, StrategyType.CRLF_INJECTION_CHECK,
            StrategyType.LOG_INJECTION_CHECK,
        ],
        "authentication": [
            StrategyType.AUTH_BYPASS_CHECK, StrategyType.BROKEN_AUTH_FLOW,
            StrategyType.SESSION_FIXATION_CHECK, StrategyType.JWT_VULNERABILITY_SCAN,
            StrategyType.OAUTH_MISCONFIGURATION, StrategyType.PRIVILEGE_ESCALATION_PATH,
            StrategyType.TOKEN_ENTROPY_CHECK, StrategyType.COOKIE_SECURITY_AUDIT,
            StrategyType.PASSWORD_STORAGE_AUDIT,
        ],
        "cryptography": [
            StrategyType.WEAK_ALGORITHM_SCAN, StrategyType.KEY_MANAGEMENT_AUDIT,
            StrategyType.IV_REUSE_DETECTION, StrategyType.PADDING_ORACLE_CHECK,
            StrategyType.HASH_WITHOUT_SALT, StrategyType.INSECURE_RANDOM_CHECK,
            StrategyType.CERTIFICATE_VALIDATION_CHECK, StrategyType.TLS_CONFIGURATION_AUDIT,
        ],
        "logic": [
            StrategyType.BRANCH_COVERAGE_ANALYSIS, StrategyType.DEAD_CODE_DETECTION,
            StrategyType.EXCEPTION_PATH_ANALYSIS, StrategyType.RACE_CONDITION_CHECK,
            StrategyType.TOCTOU_DETECTION, StrategyType.BUSINESS_LOGIC_BYPASS,
            StrategyType.INTEGER_OVERFLOW_CHECK, StrategyType.NULL_DEREFERENCE_SCAN,
            StrategyType.INFINITE_LOOP_DETECTION, StrategyType.RECURSION_DEPTH_CHECK,
        ],
        "data_flow": [
            StrategyType.TAINT_PROPAGATION_DEEP, StrategyType.SENSITIVE_DATA_FLOW,
            StrategyType.PII_EXPOSURE_CHECK, StrategyType.LOGGING_SECRETS_CHECK,
            StrategyType.ERROR_INFO_LEAK, StrategyType.STACK_TRACE_EXPOSURE,
        ],
        "network": [
            StrategyType.SSRF_DEEP_SCAN, StrategyType.DNS_REBINDING_CHECK,
            StrategyType.OPEN_REDIRECT_CHECK, StrategyType.WEBHOOK_INJECTION_CHECK,
            StrategyType.CORS_MISCONFIGURATION_CHECK,
        ],
        "supply_chain": [
            StrategyType.DEPENDENCY_CONFUSION, StrategyType.TYPOSQUATTING_CHECK,
            StrategyType.MALICIOUS_PACKAGE_SCAN,
        ],
        "serialization": [
            StrategyType.UNSAFE_DESERIALIZE_SCAN, StrategyType.GADGET_CHAIN_DETECTION,
            StrategyType.TYPE_CONFUSION_CHECK, StrategyType.PROTOTYPE_POLLUTION_CHECK,
        ],
    }

    # Compound vulnerability chains — pairs of vulns that together are more severe
    COMPOUND_CHAINS = [
        {"name": "Unauthenticated SQLi", "chain": [StrategyType.AUTH_BYPASS_CHECK, StrategyType.SQL_INJECTION_DEEP], "severity": "critical"},
        {"name": "SSRF → Cloud Metadata", "chain": [StrategyType.SSRF_DEEP_SCAN, StrategyType.SENSITIVE_DATA_FLOW], "severity": "critical"},
        {"name": "Deserialize → RCE", "chain": [StrategyType.UNSAFE_DESERIALIZE_SCAN, StrategyType.COMMAND_INJECTION_CHAIN], "severity": "critical"},
        {"name": "SSTI → Full Server", "chain": [StrategyType.SSTI_DETECTION, StrategyType.PRIVILEGE_ESCALATION_PATH], "severity": "critical"},
        {"name": "Auth Bypass → Mass Assign", "chain": [StrategyType.AUTH_BYPASS_CHECK, StrategyType.MASS_ASSIGNMENT_CHECK], "severity": "critical"},
        {"name": "Open Redirect → Phishing", "chain": [StrategyType.OPEN_REDIRECT_CHECK, StrategyType.SESSION_FIXATION_CHECK], "severity": "high"},
        {"name": "CORS → Token Theft", "chain": [StrategyType.CORS_MISCONFIGURATION_CHECK, StrategyType.JWT_VULNERABILITY_SCAN], "severity": "high"},
        {"name": "XSS → Session Hijack", "chain": [StrategyType.XSS_CONTEXT_ANALYSIS, StrategyType.COOKIE_SECURITY_AUDIT], "severity": "high"},
        {"name": "Path Traversal → Source Leak", "chain": [StrategyType.PATH_TRAVERSAL_DEEP, StrategyType.SENSITIVE_DATA_FLOW], "severity": "high"},
        {"name": "IDOR → Data Scrape", "chain": [StrategyType.IDOR_PATTERN_CHECK, StrategyType.PII_EXPOSURE_CHECK], "severity": "high"},
    ]

    def generate_multi_dimensional_scenarios(
        self,
        artifacts: list[Artifact],
        dimensions: list[str] | None = None,
        iteration: int = 0,
    ) -> list[Scenario]:
        """
        Generate scenarios across multiple vulnerability dimensions.

        Each artifact is analyzed from every specified dimension's perspective,
        producing a comprehensive multi-angle analysis plan.

        Args:
            artifacts: Discovered artifacts.
            dimensions: Which dimensions to analyze (None = all).
            iteration: Current loop iteration.

        Returns:
            Scenario list covering all requested dimensions.
        """
        if dimensions is None:
            dimensions = list(self.VULNERABILITY_DIMENSIONS.keys())

        scenarios = []

        for artifact in artifacts:
            for dim_name in dimensions:
                dim_strategies = self.VULNERABILITY_DIMENSIONS.get(dim_name, [])

                for strategy in dim_strategies:
                    scenario = Scenario(
                        strategy=strategy,
                        target_artifact=artifact,
                        parameters={"dimension": dim_name},
                        priority=0.7 * artifact.confidence,
                        provenance=f"MIRO-MULTIDIM-{dim_name.upper()}: {strategy.name}",
                        iteration=iteration,
                    )
                    scenarios.append(scenario)

        # Sort and cap
        scenarios.sort(key=lambda s: s.priority, reverse=True)
        return scenarios[:self.MAX_SCENARIOS_PER_ITERATION]

    def generate_compound_scenarios(
        self,
        artifacts: list[Artifact],
        iteration: int = 0,
    ) -> list[Scenario]:
        """
        Generate compound vulnerability chain scenarios.

        These test for vulnerability combinations that together create
        more severe security issues than any single vulnerability.

        Returns scenarios for each chain link, tagged with chain metadata.
        """
        scenarios = []

        for artifact in artifacts:
            for chain_def in self.COMPOUND_CHAINS:
                chain_name = chain_def["name"]
                chain_strategies = chain_def["chain"]
                chain_severity = chain_def["severity"]

                for idx, strategy in enumerate(chain_strategies):
                    scenario = Scenario(
                        strategy=strategy,
                        target_artifact=artifact,
                        parameters={
                            "compound_chain": chain_name,
                            "chain_position": idx,
                            "chain_length": len(chain_strategies),
                            "chain_severity": chain_severity,
                        },
                        priority=0.9 * artifact.confidence,
                        provenance=f"MIRO-COMPOUND-{chain_name}: step {idx+1}/{len(chain_strategies)}",
                        iteration=iteration,
                    )
                    scenarios.append(scenario)

        scenarios.sort(key=lambda s: s.priority, reverse=True)
        return scenarios[:self.MAX_SCENARIOS_PER_ITERATION]

    def mutate_scenario(self, scenario: Scenario, failure_reason: str = "") -> Scenario | None:
        """
        Generate a mutated variant of a failed scenario.

        Uses predetermined mutation operators — no randomness or generation.
        Returns None if no mutation is available.
        """
        mutations = {
            # Original mutations
            StrategyType.SQL_INJECTION_DEEP: StrategyType.SSTI_DETECTION,
            StrategyType.XSS_CONTEXT_ANALYSIS: StrategyType.CRLF_INJECTION_CHECK,
            StrategyType.COMMAND_INJECTION_CHAIN: StrategyType.HEADER_INJECTION_CHECK,
            StrategyType.AUTH_BYPASS_CHECK: StrategyType.PRIVILEGE_ESCALATION_PATH,
            StrategyType.PARAMETER_INJECTION_PROBE: StrategyType.MASS_ASSIGNMENT_CHECK,
            StrategyType.SSRF_DEEP_SCAN: StrategyType.DNS_REBINDING_CHECK,
            StrategyType.WEAK_ALGORITHM_SCAN: StrategyType.INSECURE_RANDOM_CHECK,
            StrategyType.SESSION_FIXATION_CHECK: StrategyType.COOKIE_SECURITY_AUDIT,
            StrategyType.UNSAFE_DESERIALIZE_SCAN: StrategyType.PROTOTYPE_POLLUTION_CHECK,
            StrategyType.PATH_TRAVERSAL_DEEP: StrategyType.FILE_INCLUSION_CHECK,
            StrategyType.BRANCH_COVERAGE_ANALYSIS: StrategyType.DEAD_CODE_DETECTION,
            StrategyType.ENTROPY_SCAN: StrategyType.DEOBFUSCATION_ATTEMPT,
            StrategyType.CORS_MISCONFIGURATION_CHECK: StrategyType.OPEN_REDIRECT_CHECK,
            StrategyType.RATE_LIMIT_PROBE: StrategyType.BUSINESS_LOGIC_BYPASS,
            StrategyType.JWT_VULNERABILITY_SCAN: StrategyType.BROKEN_AUTH_FLOW,
            StrategyType.TAINT_PROPAGATION_DEEP: StrategyType.SENSITIVE_DATA_FLOW,
            StrategyType.ERROR_INFO_LEAK: StrategyType.LOGGING_SECRETS_CHECK,
            # New mutations for expanded vulnerability classes
            StrategyType.SSTI_DETECTION: StrategyType.COMMAND_INJECTION_CHAIN,
            StrategyType.LDAP_INJECTION_CHECK: StrategyType.XPATH_INJECTION_CHECK,
            StrategyType.XPATH_INJECTION_CHECK: StrategyType.SQL_INJECTION_DEEP,
            StrategyType.HEADER_INJECTION_CHECK: StrategyType.LOG_INJECTION_CHECK,
            StrategyType.CRLF_INJECTION_CHECK: StrategyType.HEADER_INJECTION_CHECK,
            StrategyType.LOG_INJECTION_CHECK: StrategyType.ERROR_INFO_LEAK,
            StrategyType.PROTOTYPE_POLLUTION_CHECK: StrategyType.TYPE_CONFUSION_CHECK,
            StrategyType.RACE_CONDITION_CHECK: StrategyType.TOCTOU_DETECTION,
            StrategyType.TOCTOU_DETECTION: StrategyType.TEMP_FILE_RACE,
            StrategyType.INTEGER_OVERFLOW_CHECK: StrategyType.NULL_DEREFERENCE_SCAN,
            StrategyType.NULL_DEREFERENCE_SCAN: StrategyType.RESOURCE_LEAK_DETECTION,
            StrategyType.OPEN_REDIRECT_CHECK: StrategyType.XSS_CONTEXT_ANALYSIS,
            StrategyType.DNS_REBINDING_CHECK: StrategyType.WEBHOOK_INJECTION_CHECK,
            StrategyType.DEPENDENCY_CONFUSION: StrategyType.TYPOSQUATTING_CHECK,
            StrategyType.FILE_UPLOAD_BYPASS: StrategyType.PATH_TRAVERSAL_DEEP,
            StrategyType.GADGET_CHAIN_DETECTION: StrategyType.UNSAFE_DESERIALIZE_SCAN,
            StrategyType.OAUTH_MISCONFIGURATION: StrategyType.JWT_VULNERABILITY_SCAN,
            StrategyType.BROKEN_AUTH_FLOW: StrategyType.SESSION_FIXATION_CHECK,
            StrategyType.PRIVILEGE_ESCALATION_PATH: StrategyType.AUTH_BYPASS_CHECK,
            StrategyType.IDOR_PATTERN_CHECK: StrategyType.BOLA_PATTERN_CHECK,
            StrategyType.MASS_ASSIGNMENT_CHECK: StrategyType.IDOR_PATTERN_CHECK,
            StrategyType.SENSITIVE_DATA_FLOW: StrategyType.PII_EXPOSURE_CHECK,
            StrategyType.STACK_TRACE_EXPOSURE: StrategyType.ERROR_INFO_LEAK,
            StrategyType.FILE_INCLUSION_CHECK: StrategyType.SYMLINK_ATTACK_CHECK,
        }

        new_strategy = mutations.get(scenario.strategy)
        if new_strategy is None:
            return None

        return Scenario(
            strategy=new_strategy,
            target_artifact=scenario.target_artifact,
            parameters={**scenario.parameters, "mutated_from": scenario.strategy.name, "reason": failure_reason},
            priority=scenario.priority * 0.8,  # Slightly lower priority for mutations
            provenance=f"MUTATION of {scenario.provenance}",
            iteration=scenario.iteration,
            parent_scenario_id=scenario.scenario_id,
        )
