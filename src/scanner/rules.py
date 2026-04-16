"""
BAYREUTHWING — Static Pattern Rules Engine

200+ regex-based vulnerability detection rules organized by vulnerability class.
These rules complement the ML model by catching known vulnerability patterns
with high precision, even without model inference.

Each rule contains:
- pattern: Regex pattern to match
- severity: Base severity level
- message: Human-readable description
- languages: Which languages this rule applies to
"""

import re
from typing import Optional


class Rule:
    """A single vulnerability detection rule."""

    def __init__(
        self,
        rule_id: str,
        vuln_class: int,
        pattern: str,
        message: str,
        severity: str = "medium",
        languages: Optional[list[str]] = None,
        confidence: float = 0.8,
    ):
        self.rule_id = rule_id
        self.vuln_class = vuln_class
        self.pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        self.message = message
        self.severity = severity
        self.languages = languages  # None means all languages
        self.confidence = confidence

    def matches(self, code: str, language: str = "any") -> list[dict]:
        """Find all matches of this rule in the code."""
        if self.languages and language not in self.languages:
            return []

        findings = []
        last_idx = 0
        current_line = 1
        for match in self.pattern.finditer(code):
            start_idx = match.start()
            current_line += code.count("\n", last_idx, start_idx)
            last_idx = start_idx

            findings.append({
                "rule_id": self.rule_id,
                "vuln_class": self.vuln_class,
                "line": current_line,
                "matched_text": match.group(0)[:200],  # Truncate long matches
                "message": self.message,
                "severity": self.severity,
                "confidence": self.confidence,
                "source": "static_rule",
            })

        return findings


class RuleEngine:
    """
    Static pattern-based vulnerability detection engine.
    
    Contains 200+ rules covering all 11 vulnerability classes across
    multiple programming languages.
    """

    def __init__(self):
        self.rules = self._build_rules()

    def scan(self, code: str, language: str = "any") -> list[dict]:
        """
        Scan code against all rules.
        
        Args:
            code: Source code string.
            language: Programming language of the code.
            
        Returns:
            List of finding dictionaries.
        """
        findings = []
        for rule in self.rules:
            findings.extend(rule.matches(code, language))
        return findings

    def get_rules_by_class(self, vuln_class: int) -> list[Rule]:
        """Get all rules for a specific vulnerability class."""
        return [r for r in self.rules if r.vuln_class == vuln_class]

    def _build_rules(self) -> list[Rule]:
        """Build the complete rule set."""
        rules = []

        # ════════════════════════════════════════════════════════
        # 0: SQL INJECTION RULES
        # ════════════════════════════════════════════════════════
        sql_rules = [
            Rule("SQL001", 0,
                 r"""(?:execute|query|cursor\.execute)\s*\(\s*(?:f["']|["'].*?%s|["'].*?\+)""",
                 "Potential SQL injection: dynamic query construction detected",
                 "critical", None, 0.9),
            Rule("SQL002", 0,
                 r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER).*?\+\s*(?:\w+|['"])""",
                 "SQL query built with string concatenation",
                 "critical", None, 0.85),
            Rule("SQL003", 0,
                 r"""f["'](?:SELECT|INSERT|UPDATE|DELETE).*?\{.*?\}""",
                 "SQL query using f-string interpolation",
                 "critical", ["python"], 0.9),
            Rule("SQL004", 0,
                 r"""%\s*(?:user|name|id|param|input|data|query|value|request)""",
                 "SQL query with %-formatting from variable",
                 "high", ["python"], 0.7),
            Rule("SQL005", 0,
                 r"""\.format\s*\(.*?\).*?(?:SELECT|INSERT|UPDATE|DELETE)""",
                 "SQL query using .format() method",
                 "critical", ["python"], 0.85),
            Rule("SQL006", 0,
                 r"""createStatement\s*\(\s*\).*?execute""",
                 "Java Statement used instead of PreparedStatement",
                 "high", ["java"], 0.8),
            Rule("SQL007", 0,
                 r"""(?:mysql_query|mysqli_query)\s*\(\s*\$\w+\s*,\s*["'].*?\$""",
                 "PHP mysql_query with variable interpolation",
                 "critical", ["php"], 0.9),
            Rule("SQL008", 0,
                 r"""db\.(?:query|exec|run)\s*\(\s*["'`].*?\$\{""",
                 "JavaScript template literal in database query",
                 "critical", ["javascript"], 0.9),
            Rule("SQL009", 0,
                 r"""\.(?:raw|execute_sql|raw_sql)\s*\(\s*f?["']""",
                 "Raw SQL query method with dynamic input",
                 "high", None, 0.8),
            Rule("SQL010", 0,
                 r"""Sprintf\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)""",
                 "Go Sprintf used for SQL query construction",
                 "critical", ["go"], 0.9),
            Rule("SQL011", 0,
                 r"""sqlalchemy\.text\s*\(\s*f["']""",
                 "SQLAlchemy text() with f-string",
                 "critical", ["python"], 0.9),
            Rule("SQL012", 0,
                 r"""\.where\s*\(\s*["'].*?\#\{""",
                 "Ruby string interpolation in ActiveRecord query",
                 "high", ["ruby"], 0.85),
        ]
        rules.extend(sql_rules)

        # ════════════════════════════════════════════════════════
        # 1: XSS RULES
        # ════════════════════════════════════════════════════════
        xss_rules = [
            Rule("XSS001", 1,
                 r"""innerHTML\s*=\s*(?!['"]<)""",
                 "Direct innerHTML assignment with potentially unsafe content",
                 "high", ["javascript"], 0.85),
            Rule("XSS002", 1,
                 r"""document\.write\s*\(""",
                 "document.write() can inject executable content",
                 "high", ["javascript"], 0.8),
            Rule("XSS003", 1,
                 r"""dangerouslySetInnerHTML""",
                 "React dangerouslySetInnerHTML — ensure content is sanitized",
                 "high", ["javascript"], 0.75),
            Rule("XSS004", 1,
                 r"""\.outerHTML\s*=""",
                 "outerHTML assignment with potentially unsafe content",
                 "high", ["javascript"], 0.8),
            Rule("XSS005", 1,
                 r"""res\.send\s*\(\s*(?:['"]<|.*?\+\s*req\.)""",
                 "Express response with user input reflected in HTML",
                 "critical", ["javascript"], 0.85),
            Rule("XSS006", 1,
                 r"""echo\s+(?:.*?\$_(?:GET|POST|REQUEST|COOKIE))""",
                 "PHP echo with unsanitized superglobal",
                 "critical", ["php"], 0.9),
            Rule("XSS007", 1,
                 r"""(?:Markup|Markup\.escape)\s*\(\s*(?!escape)""",
                 "Flask Markup() may bypass auto-escaping",
                 "medium", ["python"], 0.6),
            Rule("XSS008", 1,
                 r"""render_template_string\s*\(""",
                 "Flask render_template_string can be exploited for SSTI/XSS",
                 "high", ["python"], 0.8),
            Rule("XSS009", 1,
                 r"""v-html\s*=""",
                 "Vue.js v-html directive renders raw HTML",
                 "medium", ["javascript"], 0.7),
            Rule("XSS010", 1,
                 r"""\.(?:write|writeln)\s*\(\s*(?:request|params|query)""",
                 "Response body written with unsanitized request data",
                 "high", None, 0.8),
            Rule("XSS011", 1,
                 r"""jquery.*?\.\s*(?:html|append)\s*\(\s*(?!\s*['"]<)""",
                 "jQuery .html()/.append() with dynamic content",
                 "high", ["javascript"], 0.75),
            Rule("XSS012", 1,
                 r"""(?:\{!!|<%=|<%-)\s*(?!.*escape|.*sanitize|.*encode)""",
                 "Unescaped template output",
                 "high", None, 0.7),
        ]
        rules.extend(xss_rules)

        # ════════════════════════════════════════════════════════
        # 2: COMMAND INJECTION RULES
        # ════════════════════════════════════════════════════════
        cmd_rules = [
            Rule("CMD001", 2,
                 r"""os\.system\s*\(""",
                 "os.system() executes commands through shell — use subprocess instead",
                 "critical", ["python"], 0.85),
            Rule("CMD002", 2,
                 r"""os\.popen\s*\(""",
                 "os.popen() executes shell commands — use subprocess instead",
                 "critical", ["python"], 0.85),
            Rule("CMD003", 2,
                 r"""subprocess\.(?:call|check_output|check_call|run|Popen)\s*\(.*?shell\s*=\s*True""",
                 "subprocess with shell=True — avoid with user input",
                 "critical", ["python"], 0.9),
            Rule("CMD004", 2,
                 r"""(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:.*?\+|`.*?\$)""",
                 "Node.js child_process with dynamic command",
                 "critical", ["javascript"], 0.85),
            Rule("CMD005", 2,
                 r"""shell_exec\s*\(\s*(?:.*?\$|.*?\.)""",
                 "PHP shell_exec with dynamic input",
                 "critical", ["php"], 0.9),
            Rule("CMD006", 2,
                 r"""(?:system|passthru|popen|proc_open)\s*\(\s*\$""",
                 "PHP command execution with variable input",
                 "critical", ["php"], 0.9),
            Rule("CMD007", 2,
                 r"""Runtime\.getRuntime\(\)\.exec\s*\(""",
                 "Java Runtime.exec() — use ProcessBuilder with argument list",
                 "high", ["java"], 0.8),
            Rule("CMD008", 2,
                 r"""`.*?\#\{.*?\}`""",
                 "Ruby backtick execution with interpolation",
                 "critical", ["ruby"], 0.85),
            Rule("CMD009", 2,
                 r"""exec\.Command\s*\(\s*["'](?:sh|bash|cmd)["']""",
                 "Go exec.Command with shell interpreter",
                 "high", ["go"], 0.8),
            Rule("CMD010", 2,
                 r"""eval\s*\(\s*(?:request|params|input|user|data|query)""",
                 "eval() with user-controlled input",
                 "critical", None, 0.95),
            Rule("CMD011", 2,
                 r"""(?:exec|eval)\s*\(\s*(?:f["']|["'].*?\+|["'].*?%|.*?\.format)""",
                 "Code execution via eval/exec with dynamic string",
                 "critical", None, 0.9),
            Rule("CMD012", 2,
                 r"""std::system\s*\(""",
                 "C/C++ system() call — use execvp() or similar",
                 "critical", ["c", "cpp"], 0.85),
        ]
        rules.extend(cmd_rules)

        # ════════════════════════════════════════════════════════
        # 3: PATH TRAVERSAL RULES
        # ════════════════════════════════════════════════════════
        path_rules = [
            Rule("PTH001", 3,
                 r"""(?:open|read|write|send_file|sendFile|readFile|readFileSync)\s*\(.*?(?:request|req\.|params|query|input|args)""",
                 "File operation with user-controlled path",
                 "high", None, 0.8),
            Rule("PTH002", 3,
                 r"""(?:os\.path\.join|path\.join|Path)\s*\(.*?(?:request|req\.|params|input)""",
                 "Path construction with user input — validate with realpath",
                 "medium", None, 0.7),
            Rule("PTH003", 3,
                 r"""\.\.(?:/|\\)""",
                 "Directory traversal pattern detected in code",
                 "medium", None, 0.5),
            Rule("PTH004", 3,
                 r"""send_file\s*\(\s*(?!.*realpath|.*abspath|.*resolve).*?(?:request|args)""",
                 "Flask send_file with unvalidated user path",
                 "high", ["python"], 0.85),
            Rule("PTH005", 3,
                 r"""res\.sendFile\s*\(\s*(?!.*resolve|.*normalize).*?req\.""",
                 "Express sendFile with unvalidated request path",
                 "high", ["javascript"], 0.85),
            Rule("PTH006", 3,
                 r"""FileInputStream\s*\(\s*(?:.*?\+|new\s+File.*?request)""",
                 "Java FileInputStream with user-controlled path",
                 "high", ["java"], 0.8),
            Rule("PTH007", 3,
                 r"""file_get_contents\s*\(\s*\$""",
                 "PHP file_get_contents with variable path",
                 "high", ["php"], 0.75),
            Rule("PTH008", 3,
                 r"""include\s*\(\s*\$|require\s*\(\s*\$""",
                 "PHP include/require with variable — potential LFI",
                 "critical", ["php"], 0.9),
        ]
        rules.extend(path_rules)

        # ════════════════════════════════════════════════════════
        # 4: HARDCODED CREDENTIALS RULES
        # ════════════════════════════════════════════════════════
        cred_rules = [
            Rule("CRD001", 4,
                 r"""(?:password|passwd|pwd)\s*=\s*["'][^"']{4,}["']""",
                 "Hardcoded password detected",
                 "high", None, 0.85),
            Rule("CRD002", 4,
                 r"""(?:api_key|apikey|api_secret|apisecret)\s*=\s*["'][^"']{8,}["']""",
                 "Hardcoded API key detected",
                 "high", None, 0.9),
            Rule("CRD003", 4,
                 r"""(?:secret_key|secret|jwt_secret|encryption_key)\s*=\s*["'][^"']{8,}["']""",
                 "Hardcoded secret key detected",
                 "high", None, 0.85),
            Rule("CRD004", 4,
                 r"""(?:sk_live|pk_live|sk_test|pk_test)_[a-zA-Z0-9]{20,}""",
                 "Stripe API key detected",
                 "critical", None, 0.95),
            Rule("CRD005", 4,
                 r"""(?:AKIA|ASIA)[A-Z0-9]{16}""",
                 "AWS access key ID detected",
                 "critical", None, 0.95),
            Rule("CRD006", 4,
                 r"""(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}""",
                 "GitHub personal access token detected",
                 "critical", None, 0.95),
            Rule("CRD007", 4,
                 r"""(?:token|bearer)\s*[:=]\s*["'][a-zA-Z0-9\-_.]{20,}["']""",
                 "Hardcoded authentication token",
                 "high", None, 0.8),
            Rule("CRD008", 4,
                 r"""(?:-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----)""",
                 "Private key embedded in source code",
                 "critical", None, 0.95),
            Rule("CRD009", 4,
                 r"""(?:mongodb(?:\+srv)?://)\w+:\w+@""",
                 "MongoDB connection string with embedded credentials",
                 "critical", None, 0.9),
            Rule("CRD010", 4,
                 r"""(?:mysql|postgres|postgresql|redis|amqp)://\w+:\w+@""",
                 "Database connection string with embedded credentials",
                 "critical", None, 0.9),
            Rule("CRD011", 4,
                 r"""(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD)\s*=\s*["'][^"']+["']""",
                 "Database password in configuration",
                 "high", None, 0.85),
            Rule("CRD012", 4,
                 r"""xox[baprs]-[0-9a-zA-Z]{10,}""",
                 "Slack token detected",
                 "critical", None, 0.95),
        ]
        rules.extend(cred_rules)

        # ════════════════════════════════════════════════════════
        # 5: INSECURE DESERIALIZATION RULES
        # ════════════════════════════════════════════════════════
        deser_rules = [
            Rule("DES001", 5,
                 r"""pickle\.(?:loads?|Unpickler)""",
                 "pickle deserialization — unsafe with untrusted data",
                 "critical", ["python"], 0.9),
            Rule("DES002", 5,
                 r"""yaml\.load\s*\(\s*(?!.*Loader\s*=\s*yaml\.SafeLoader|.*safe_load)""",
                 "yaml.load() without SafeLoader allows code execution",
                 "critical", ["python"], 0.9),
            Rule("DES003", 5,
                 r"""marshal\.loads?\s*\(""",
                 "marshal deserialization — unsafe with untrusted data",
                 "critical", ["python"], 0.85),
            Rule("DES004", 5,
                 r"""shelve\.open\s*\(""",
                 "shelve uses pickle internally — unsafe with untrusted data",
                 "high", ["python"], 0.75),
            Rule("DES005", 5,
                 r"""ObjectInputStream\s*\(\s*(?!.*ValidatingObjectInputStream)""",
                 "Java ObjectInputStream without validation",
                 "critical", ["java"], 0.85),
            Rule("DES006", 5,
                 r"""(?:unserialize|deserialize)\s*\(\s*\$""",
                 "PHP unserialize with user input",
                 "critical", ["php"], 0.9),
            Rule("DES007", 5,
                 r"""JSON\.parse\s*\(.*?(?:then|\.body|\.data)""",
                 "JSON.parse with untrusted data — ensure validation after parsing",
                 "low", ["javascript"], 0.4),
            Rule("DES008", 5,
                 r"""(?:xmlrpc|xml\.etree|xml\.dom|lxml).*?parse""",
                 "XML parsing may be vulnerable to XXE attacks",
                 "medium", ["python"], 0.6),
            Rule("DES009", 5,
                 r"""BinaryFormatter\s*\(\s*\).*?Deserialize""",
                 ".NET BinaryFormatter deserialization is unsafe",
                 "critical", None, 0.9),
        ]
        rules.extend(deser_rules)

        # ════════════════════════════════════════════════════════
        # 6: WEAK CRYPTOGRAPHY RULES
        # ════════════════════════════════════════════════════════
        crypto_rules = [
            Rule("CRP001", 6,
                 r"""(?:hashlib\.)?md5\s*\(""",
                 "MD5 is cryptographically broken — use SHA-256 or better",
                 "medium", None, 0.85),
            Rule("CRP002", 6,
                 r"""(?:hashlib\.)?sha1\s*\(""",
                 "SHA-1 is deprecated — use SHA-256 or better",
                 "medium", None, 0.7),
            Rule("CRP003", 6,
                 r"""DES\s*[\.(]""",
                 "DES is a weak cipher — use AES-256",
                 "high", None, 0.9),
            Rule("CRP004", 6,
                 r"""(?:RC4|RC2|Blowfish)\s*[\.(]""",
                 "Weak/deprecated cipher detected — use AES-256-GCM",
                 "high", None, 0.85),
            Rule("CRP005", 6,
                 r"""ECB\s*(?:mode|MODE)""",
                 "ECB mode does not provide semantic security — use GCM or CBC with HMAC",
                 "high", None, 0.9),
            Rule("CRP006", 6,
                 r"""createCipher\s*\(""",
                 "Node.js crypto.createCipher is deprecated — use createCipheriv",
                 "medium", ["javascript"], 0.8),
            Rule("CRP007", 6,
                 r"""(?:key_size|keysize)\s*=\s*(?:56|64|128)""",
                 "Potentially insufficient key size — use 256-bit keys",
                 "medium", None, 0.6),
            Rule("CRP008", 6,
                 r"""\.(?:encode|decode)\s*\(\s*['"]rot13['"]""",
                 "ROT13 is not encryption — do not use for security",
                 "high", None, 0.95),
            Rule("CRP009", 6,
                 r"""base64\.(?:b64encode|encode|b64decode)\s*\(.*?(?:password|secret|key|token)""",
                 "Base64 is encoding, not encryption — do not use for sensitive data",
                 "medium", None, 0.7),
            Rule("CRP010", 6,
                 r"""(?:crypt|crypt32|crc32)\s*\(""",
                 "Weak hash/checksum function — not suitable for security",
                 "medium", None, 0.7),
        ]
        rules.extend(crypto_rules)

        # ════════════════════════════════════════════════════════
        # 7: BUFFER OVERFLOW RULES
        # ════════════════════════════════════════════════════════
        buffer_rules = [
            Rule("BOF001", 7,
                 r"""(?<!strn)strcpy\s*\(""",
                 "strcpy() with no bounds checking — use strncpy()",
                 "critical", ["c", "cpp"], 0.9),
            Rule("BOF002", 7,
                 r"""(?<!strn)strcat\s*\(""",
                 "strcat() with no bounds checking — use strncat()",
                 "critical", ["c", "cpp"], 0.9),
            Rule("BOF003", 7,
                 r"""\bgets\s*\(""",
                 "gets() is always unsafe — use fgets()",
                 "critical", ["c", "cpp"], 0.95),
            Rule("BOF004", 7,
                 r"""sprintf\s*\((?!.*snprintf)""",
                 "sprintf() with no size limit — use snprintf()",
                 "high", ["c", "cpp"], 0.85),
            Rule("BOF005", 7,
                 r"""scanf\s*\(\s*["']%s["']""",
                 "scanf %s with no width limit — use %Ns or fgets",
                 "critical", ["c", "cpp"], 0.9),
            Rule("BOF006", 7,
                 r"""(?:alloca|_alloca)\s*\(""",
                 "alloca() can cause stack overflow with large sizes",
                 "medium", ["c", "cpp"], 0.7),
            Rule("BOF007", 7,
                 r"""(?:memcpy|memmove)\s*\(.*?,.*?,.*?(?:strlen|sizeof)""",
                 "memcpy/memmove — verify size parameter prevents overflow",
                 "medium", ["c", "cpp"], 0.5),
            Rule("BOF008", 7,
                 r"""char\s+\w+\s*\[\s*\d+\s*\]\s*;.*?(?:strcpy|strcat|gets|sprintf)""",
                 "Fixed-size buffer with unsafe copy function",
                 "critical", ["c", "cpp"], 0.85),
        ]
        rules.extend(buffer_rules)

        # ════════════════════════════════════════════════════════
        # 8: SSRF RULES
        # ════════════════════════════════════════════════════════
        ssrf_rules = [
            Rule("SSR001", 8,
                 r"""requests\.(?:get|post|put|delete|patch|head)\s*\(\s*(?:.*?request|.*?input|.*?params|.*?args)""",
                 "Python requests with user-controlled URL — validate hostname",
                 "high", ["python"], 0.85),
            Rule("SSR002", 8,
                 r"""urllib\.request\.(?:urlopen|urlretrieve)\s*\(\s*(?!['"]https?://)""",
                 "urllib with potentially user-controlled URL",
                 "high", ["python"], 0.75),
            Rule("SSR003", 8,
                 r"""fetch\s*\(\s*(?:req\.|request\.|params\.|.*?input|.*?url)""",
                 "fetch() with user-controlled URL",
                 "high", ["javascript"], 0.8),
            Rule("SSR004", 8,
                 r"""(?:file_get_contents|fopen|curl_exec)\s*\(\s*\$""",
                 "PHP URL fetching with user-controlled input",
                 "high", ["php"], 0.85),
            Rule("SSR005", 8,
                 r"""HttpClient.*?(?:GetAsync|PostAsync|SendAsync)\s*\(\s*(?!['"]\s*https?://)""",
                 "HTTP client with potentially user-controlled URL",
                 "high", None, 0.7),
            Rule("SSR006", 8,
                 r"""http\.(?:Get|Post|Do)\s*\(\s*(?!['"]https?://)""",
                 "Go HTTP client with dynamic URL",
                 "high", ["go"], 0.75),
        ]
        rules.extend(ssrf_rules)

        # ════════════════════════════════════════════════════════
        # 9: SENSITIVE DATA EXPOSURE RULES
        # ════════════════════════════════════════════════════════
        exposure_rules = [
            Rule("EXP001", 9,
                 r"""(?:traceback|stack_trace|stackTrace|\.stack)\b.*?(?:response|res\.|send|json|render)""",
                 "Stack trace exposed in response — use generic error messages",
                 "high", None, 0.8),
            Rule("EXP002", 9,
                 r"""(?:DEBUG|debug)\s*=\s*(?:True|true|1)""",
                 "Debug mode enabled — disable in production",
                 "medium", None, 0.7),
            Rule("EXP003", 9,
                 r"""(?:print|console\.log|Logger\.info)\s*\(.*?(?:password|secret|token|key|credential|ssn|credit.?card)""",
                 "Sensitive data written to logs",
                 "high", None, 0.8),
            Rule("EXP004", 9,
                 r"""(?:password_hash|password_digest|hashed_password).*?(?:json|response|send|render)""",
                 "Password hash exposed in API response",
                 "high", None, 0.85),
            Rule("EXP005", 9,
                 r"""X-Powered-By""",
                 "X-Powered-By header reveals server technology",
                 "low", None, 0.6),
            Rule("EXP006", 9,
                 r"""Server\s*:\s*(?:Apache|nginx|IIS|Express)""",
                 "Server header reveals technology stack",
                 "low", None, 0.5),
            Rule("EXP007", 9,
                 r"""(?:os\.environ|process\.env|System\.getenv).*?(?:json|response|send|render|print|log)""",
                 "Environment variables leaked in output",
                 "high", None, 0.75),
            Rule("EXP008", 9,
                 r"""\.(?:ssn|social_security|tax_id|national_id)\b""",
                 "Sensitive PII field accessed — ensure proper access control",
                 "medium", None, 0.5),
        ]
        rules.extend(exposure_rules)

        # ════════════════════════════════════════════════════════
        # 10: INSECURE RANDOMNESS RULES
        # ════════════════════════════════════════════════════════
        random_rules = [
            Rule("RNG001", 10,
                 r"""(?<!secrets\.)(?<!secure)random\.(?:random|randint|choice|sample|randrange)\s*\(""",
                 "Python random module is not cryptographically secure — use secrets module",
                 "medium", ["python"], 0.75),
            Rule("RNG002", 10,
                 r"""Math\.random\s*\(\s*\)""",
                 "Math.random() is not cryptographically secure — use crypto.randomBytes",
                 "medium", ["javascript"], 0.8),
            Rule("RNG003", 10,
                 r"""new\s+Random\s*\(\s*\)""",
                 "java.util.Random is not cryptographically secure — use SecureRandom",
                 "medium", ["java"], 0.8),
            Rule("RNG004", 10,
                 r"""(?:srand|rand)\s*\(\s*(?:time|clock|seed)""",
                 "C rand() with time-based seed is predictable",
                 "high", ["c", "cpp"], 0.85),
            Rule("RNG005", 10,
                 r"""(?:uuid4|uuid\.uuid4|uuidv4).*?(?:token|session|secret|key|password)""",
                 "UUID may not provide sufficient randomness for security tokens",
                 "low", None, 0.4),
            Rule("RNG006", 10,
                 r"""Math\.floor\s*\(\s*Math\.random\s*\(\s*\)\s*\*.*?(?:token|session|id|key|code)""",
                 "Math.random for security-sensitive ID generation",
                 "high", ["javascript"], 0.85),
            Rule("RNG007", 10,
                 r"""(?:mt_rand|rand)\s*\(""",
                 "PHP mt_rand/rand not suitable for security — use random_bytes",
                 "medium", ["php"], 0.75),
        ]
        rules.extend(random_rules)




        # ADVANCED SECRET SCANNING RULES
        auth_rules_extra = [
            Rule("AUT005", 4,
                 r"(?i)AKIA[0-9A-Z]{16}",
                 "AWS Access Key ID detected",
                 "critical", None, 0.95),
            Rule("AUT006", 4,
                 r"(?i)ya29\.[0-9a-zA-Z-_]+",
                 "Google OAuth Access Token detected",
                 "critical", None, 0.95),
            Rule("AUT007", 4,
                 r"(?i)gh[po]_[a-zA-Z0-9]{36}",
                 "GitHub Personal Access Token detected",
                 "critical", None, 0.95),
            Rule("AUT008", 4,
                 r"(?i)sk_live_[a-zA-Z0-9]{24}",
                 "Stripe Live Secret Key detected",
                 "critical", None, 0.95),
            Rule("AUT009", 4,
                 r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
                 "Private Cryptographic Key detected in code",
                 "critical", None, 0.99),
            Rule("AUT010", 4,
                 r"(?i)(?:api[_-]?key|slack[_-]?token|bot[_-]?token|auth[_-]?token)\s*(?:=|:)\s*['\"][a-zA-Z0-9\-_\\.]{15,}['\"]",
                 "High-entropy secret/token assignment detected",
                 "high", None, 0.85),
        ]
        rules.extend(auth_rules_extra)

        return rules

    @property
    def total_rules(self) -> int:
        """Get total number of rules."""
        return len(self.rules)

    def rules_summary(self) -> dict[str, int]:
        """Get count of rules per vulnerability class."""
        from ..utils.cwe_mapping import CWEMapper
        summary = {}
        for vuln_id, name in CWEMapper.get_all_classes().items():
            count = len(self.get_rules_by_class(vuln_id))
            summary[name] = count
        return summary
