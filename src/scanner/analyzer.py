"""
BAYREUTHWING — Code Flow Analyzer

Analyzes code control flow and data flow to detect complex vulnerability
patterns that can't be caught by simple regex rules. This module provides:

- Import/dependency analysis
- Dangerous function call detection
- Data flow tracking (simplified taint analysis)
- Framework-adaptive analysis
"""

import re
from typing import Optional
from ..data.preprocessor import CodePreprocessor


class CodeAnalyzer:
    """
    Static code flow analyzer for vulnerability detection.
    
    Performs deeper analysis than pattern matching:
    - Tracks dangerous function usage
    - Identifies import patterns that indicate security concerns
    - Detects missing security controls
    - Adapts analysis based on detected framework
    """

    # Dangerous function groups by language
    DANGEROUS_FUNCTIONS = {
        "python": {
            "exec": {"vuln_class": 2, "severity": "critical", "msg": "exec() can execute arbitrary code"},
            "eval": {"vuln_class": 2, "severity": "critical", "msg": "eval() can execute arbitrary expressions"},
            "compile": {"vuln_class": 2, "severity": "medium", "msg": "compile() dynamically creates code objects"},
            "__import__": {"vuln_class": 2, "severity": "high", "msg": "Dynamic import can load arbitrary modules"},
            "pickle.loads": {"vuln_class": 5, "severity": "critical", "msg": "pickle deserialization is unsafe"},
            "pickle.load": {"vuln_class": 5, "severity": "critical", "msg": "pickle deserialization is unsafe"},
            "os.system": {"vuln_class": 2, "severity": "critical", "msg": "os.system executes shell commands"},
            "os.popen": {"vuln_class": 2, "severity": "critical", "msg": "os.popen executes shell commands"},
        },
        "javascript": {
            "eval": {"vuln_class": 2, "severity": "critical", "msg": "eval() executes arbitrary JavaScript"},
            "Function": {"vuln_class": 2, "severity": "high", "msg": "Function constructor creates dynamic functions"},
            "setTimeout(string)": {"vuln_class": 2, "severity": "high", "msg": "setTimeout with string arg is like eval"},
            "setInterval(string)": {"vuln_class": 2, "severity": "high", "msg": "setInterval with string arg is like eval"},
        },
        "php": {
            "eval": {"vuln_class": 2, "severity": "critical", "msg": "eval() executes arbitrary PHP code"},
            "assert": {"vuln_class": 2, "severity": "high", "msg": "assert() can execute code in older PHP"},
            "preg_replace": {"vuln_class": 2, "severity": "high", "msg": "preg_replace /e modifier executes code"},
            "extract": {"vuln_class": 9, "severity": "high", "msg": "extract() overwrites variables from array"},
        },
    }

    # Security headers to check in web applications
    SECURITY_HEADERS = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    def __init__(self):
        self.preprocessor = CodePreprocessor()

    def analyze(self, code: str, filepath: Optional[str] = None) -> dict:
        """
        Perform deep code analysis.
        
        Args:
            code: Source code string.
            filepath: Optional file path for context.
            
        Returns:
            Analysis results dictionary.
        """
        # Preprocess
        preprocessed = self.preprocessor.preprocess(code, filepath)
        language = preprocessed["language"]
        frameworks = preprocessed["frameworks"]

        results = {
            "language": language,
            "frameworks": frameworks,
            "findings": [],
            "imports": self._analyze_imports(code, language),
            "dangerous_calls": self._find_dangerous_calls(code, language),
            "missing_controls": self._check_missing_controls(code, language, frameworks),
            "data_flow_risks": self._analyze_data_flow(code, language),
        }

        # Collect all findings
        for call in results["dangerous_calls"]:
            results["findings"].append({
                "vuln_class": call["vuln_class"],
                "line": call["line"],
                "message": call["message"],
                "severity": call["severity"],
                "confidence": 0.7,
                "source": "code_analysis",
            })

        for risk in results["data_flow_risks"]:
            results["findings"].append({
                "vuln_class": risk["vuln_class"],
                "line": risk.get("line", 0),
                "message": risk["message"],
                "severity": risk["severity"],
                "confidence": 0.6,
                "source": "data_flow",
            })

        for control in results["missing_controls"]:
            results["findings"].append({
                "vuln_class": control.get("vuln_class", 9),
                "line": 0,
                "message": control["message"],
                "severity": control["severity"],
                "confidence": 0.5,
                "source": "missing_control",
            })

        return results

    def _analyze_imports(self, code: str, language: str) -> list[dict]:
        """Identify security-relevant imports."""
        imports = []

        if language == "python":
            patterns = [
                (r"import\s+(pickle|shelve|marshal)", "Unsafe serialization library imported"),
                (r"from\s+xml\.etree.*?import", "XML parser may be vulnerable to XXE"),
                (r"import\s+subprocess", "subprocess module — ensure safe usage"),
                (r"from\s+Crypto\.Cipher\s+import\s+DES", "DES cipher imported — use AES"),
                (r"import\s+hashlib", "hashlib — ensure strong algorithms are used"),
                (r"import\s+random(?!\s*#.*?secure)", "random module — use secrets for security"),
            ]
        elif language == "javascript":
            patterns = [
                (r"""require\s*\(\s*['"]child_process['"]\s*\)""", "child_process — risk of command injection"),
                (r"""require\s*\(\s*['"]vm['"]\s*\)""", "vm module — risk of code injection"),
                (r"""require\s*\(\s*['"]eval['"]\s*\)""", "eval module imported"),
            ]
        else:
            patterns = []

        for pattern, message in patterns:
            # O(N) optimization: track lines incrementally
            last_idx = 0
            current_line = 1
            for match in re.finditer(pattern, code):
                current_line += code.count("\n", last_idx, match.start())
                last_idx = match.start()
                line = current_line
                imports.append({
                    "line": line,
                    "import": match.group(0),
                    "message": message,
                })

        return imports

    def _find_dangerous_calls(self, code: str, language: str) -> list[dict]:
        """Find calls to known dangerous functions."""
        findings = []
        func_map = self.DANGEROUS_FUNCTIONS.get(language, {})

        for func_name, info in func_map.items():
            # Escape dots for regex
            escaped = re.escape(func_name)
            pattern = rf"\b{escaped}\s*\("
            # O(N) optimization: track lines incrementally
            last_idx = 0
            current_line = 1
            for match in re.finditer(pattern, code):
                current_line += code.count("\n", last_idx, match.start())
                last_idx = match.start()
                line = current_line
                findings.append({
                    "function": func_name,
                    "line": line,
                    "vuln_class": info["vuln_class"],
                    "severity": info["severity"],
                    "message": info["msg"],
                })

        return findings

    def _check_missing_controls(
        self, code: str, language: str, frameworks: list[str]
    ) -> list[dict]:
        """Check for missing security controls based on framework."""
        missing = []

        # Django-specific checks
        if "django" in frameworks:
            if "CSRF" not in code and "csrf" not in code.lower():
                missing.append({
                    "message": "Django: No CSRF protection references found",
                    "severity": "medium",
                    "vuln_class": 9,
                })
            if "SECURE_SSL_REDIRECT" not in code and "settings" in code.lower():
                missing.append({
                    "message": "Django: SECURE_SSL_REDIRECT not configured",
                    "severity": "medium",
                    "vuln_class": 9,
                })

        # Flask-specific checks
        if "flask" in frameworks:
            if "csrf" not in code.lower() and "CSRFProtect" not in code:
                missing.append({
                    "message": "Flask: No CSRF protection (consider Flask-WTF)",
                    "severity": "medium",
                    "vuln_class": 9,
                })

        # Express-specific checks
        if "express" in frameworks:
            if "helmet" not in code.lower():
                missing.append({
                    "message": "Express: Consider using helmet for security headers",
                    "severity": "low",
                    "vuln_class": 9,
                })
            if "cors" not in code.lower():
                missing.append({
                    "message": "Express: CORS configuration not detected",
                    "severity": "low",
                    "vuln_class": 9,
                })
            if "rate" not in code.lower() and "limit" not in code.lower():
                missing.append({
                    "message": "Express: No rate limiting detected",
                    "severity": "medium",
                    "vuln_class": 9,
                })

        # General checks
        if language == "python":
            if "logging" not in code and "logger" not in code.lower():
                missing.append({
                    "message": "No logging configuration — security events may go unrecorded",
                    "severity": "low",
                    "vuln_class": 9,
                })

        return missing

    def _analyze_data_flow(self, code: str, language: str) -> list[dict]:
        """
        Simplified taint analysis — track user input flowing into dangerous sinks.
        
        Identifies common source → sink patterns.
        """
        risks = []

        # Sources (user input)
        sources = {
            "python": [
                r"request\.\w+",
                r"input\s*\(",
                r"sys\.argv",
                r"os\.environ",
            ],
            "javascript": [
                r"req\.\w+",
                r"request\.\w+",
                r"process\.argv",
                r"document\.(?:location|URL|cookie)",
                r"window\.location",
            ],
            "php": [
                r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\[",
                r"\$_SESSION\[",
            ],
        }

        # Sinks (dangerous operations)
        sinks = {
            "python": [
                (r"cursor\.execute\s*\(", 0, "User input may reach database query"),
                (r"os\.system\s*\(", 2, "User input may reach system command"),
                (r"subprocess\.\w+\s*\(", 2, "User input may reach subprocess"),
                (r"open\s*\(", 3, "User input may reach file operation"),
                (r"eval\s*\(", 2, "User input may reach eval()"),
                (r"render_template_string\s*\(", 1, "User input may reach template rendering"),
            ],
            "javascript": [
                (r"\.query\s*\(", 0, "User input may reach database query"),
                (r"exec\s*\(", 2, "User input may reach command execution"),
                (r"innerHTML\s*=", 1, "User input may reach innerHTML"),
                (r"eval\s*\(", 2, "User input may reach eval()"),
                (r"res\.send\s*\(", 1, "User input may reach response body"),
            ],
            "php": [
                (r"mysql(?:i)?_query\s*\(", 0, "User input may reach SQL query"),
                (r"shell_exec\s*\(", 2, "User input may reach shell command"),
                (r"echo\s+", 1, "User input may reach HTML output"),
                (r"include\s*\(", 3, "User input may reach include path"),
            ],
        }

        lang_sources = sources.get(language, [])
        lang_sinks = sinks.get(language, [])

        has_sources = any(re.search(s, code) for s in lang_sources)

        if has_sources:
            for sink_pattern, vuln_class, message in lang_sinks:
                # O(N) optimization: track lines incrementally
                last_idx = 0
                current_line = 1
                for match in re.finditer(sink_pattern, code):
                    current_line += code.count("\n", last_idx, match.start())
                    last_idx = match.start()
                    line = current_line
                    risks.append({
                        "vuln_class": vuln_class,
                        "line": line,
                        "message": message,
                        "severity": "medium",
                        "sink": match.group(0),
                    })

        return risks
