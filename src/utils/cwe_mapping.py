"""
BAYREUTHWING — CWE/OWASP Mapping

Maps vulnerability classes to CWE IDs, OWASP Top 10 categories, and
provides detailed vulnerability information including descriptions,
impact assessments, and remediation guidance.
"""


class CWEMapper:
    """
    Maps vulnerability identifiers to CWE and OWASP standards.
    
    Provides comprehensive vulnerability metadata including:
    - CWE ID and description
    - OWASP Top 10 category
    - Severity base rating
    - Impact description
    - Remediation guidance
    """

    VULNERABILITY_DATABASE = {
        0: {
            "name": "SQL Injection",
            "cwe_id": "CWE-89",
            "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
            "owasp": "A03:2021 — Injection",
            "severity": "critical",
            "description": (
                "SQL injection occurs when untrusted data is sent to an interpreter "
                "as part of a command or query. The attacker's hostile data can trick "
                "the interpreter into executing unintended commands or accessing data "
                "without proper authorization."
            ),
            "impact": (
                "Full database compromise, data theft, data manipulation, "
                "authentication bypass, and potential system-level access."
            ),
            "remediation": [
                "Use parameterized queries (prepared statements) for all database access",
                "Use an ORM (Object-Relational Mapping) framework",
                "Implement input validation with allow-lists",
                "Apply the principle of least privilege to database accounts",
                "Escape special characters if parameterized queries are not available",
            ],
        },
        1: {
            "name": "Cross-Site Scripting (XSS)",
            "cwe_id": "CWE-79",
            "cwe_name": "Improper Neutralization of Input During Web Page Generation",
            "owasp": "A03:2021 — Injection",
            "severity": "high",
            "description": (
                "XSS flaws occur when an application includes untrusted data in a web page "
                "without proper validation or escaping. This allows attackers to execute "
                "scripts in the victim's browser, hijacking user sessions, defacing websites, "
                "or redirecting the user to malicious sites."
            ),
            "impact": (
                "Session hijacking, cookie theft, credential harvesting, "
                "malware distribution, website defacement."
            ),
            "remediation": [
                "Encode output data when rendering in HTML context",
                "Use Content-Security-Policy (CSP) headers",
                "Use auto-escaping template engines",
                "Sanitize HTML input with a proven library (e.g., DOMPurify, Bleach)",
                "Avoid innerHTML; use textContent or createElement",
            ],
        },
        2: {
            "name": "Command Injection",
            "cwe_id": "CWE-78",
            "cwe_name": "Improper Neutralization of Special Elements used in an OS Command",
            "owasp": "A03:2021 — Injection",
            "severity": "critical",
            "description": (
                "Command injection occurs when an application passes unsafe user-supplied "
                "data to a system shell. An attacker can use this to execute arbitrary "
                "operating system commands on the host."
            ),
            "impact": (
                "Full system compromise, arbitrary command execution, "
                "data exfiltration, lateral movement, persistence."
            ),
            "remediation": [
                "Avoid system shell calls when possible; use language-native APIs",
                "Use argument arrays instead of shell string concatenation",
                "Never use shell=True with user-controlled input",
                "Validate and sanitize input using allow-lists",
                "Implement sandboxing and least-privilege execution",
            ],
        },
        3: {
            "name": "Path Traversal",
            "cwe_id": "CWE-22",
            "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory",
            "owasp": "A01:2021 — Broken Access Control",
            "severity": "high",
            "description": (
                "Path traversal attacks aim to access files and directories outside "
                "the intended directory. By using sequences like '../', an attacker "
                "can traverse the filesystem to read sensitive files."
            ),
            "impact": (
                "Unauthorized file access, source code disclosure, "
                "configuration leak, credential theft."
            ),
            "remediation": [
                "Validate and canonicalize file paths before use",
                "Use a chroot jail or container to limit filesystem access",
                "Implement path prefix validation (ensure resolved path starts with base)",
                "Use allow-lists for permitted file names",
                "Never use raw user input in file paths",
            ],
        },
        4: {
            "name": "Hardcoded Credentials",
            "cwe_id": "CWE-798",
            "cwe_name": "Use of Hard-coded Credentials",
            "owasp": "A07:2021 — Identification and Authentication Failures",
            "severity": "high",
            "description": (
                "Hardcoded credentials embedded in source code can be discovered "
                "through reverse engineering, code repositories, or decompilation. "
                "This provides attackers with valid credentials for authentication bypass."
            ),
            "impact": (
                "Authentication bypass, unauthorized access, lateral movement, "
                "data breach via exposed API keys."
            ),
            "remediation": [
                "Use environment variables for all secrets",
                "Implement a secrets management system (Vault, AWS Secrets Manager)",
                "Use configuration files excluded from version control (.gitignore)",
                "Rotate credentials regularly",
                "Use pre-commit hooks to detect secrets before committing",
            ],
        },
        5: {
            "name": "Insecure Deserialization",
            "cwe_id": "CWE-502",
            "cwe_name": "Deserialization of Untrusted Data",
            "owasp": "A08:2021 — Software and Data Integrity Failures",
            "severity": "critical",
            "description": (
                "Insecure deserialization occurs when untrusted data is used to abuse "
                "the logic of an application's deserialization process. This can lead to "
                "remote code execution, replay attacks, injection attacks, or privilege "
                "escalation."
            ),
            "impact": (
                "Remote code execution, denial of service, "
                "authentication bypass, object manipulation."
            ),
            "remediation": [
                "Never deserialize data from untrusted sources with native serializers",
                "Use JSON or other safe serialization formats",
                "Implement integrity checks (signatures, HMAC) on serialized data",
                "Use allow-lists for deserialization classes",
                "Run deserialization in low-privilege environments",
            ],
        },
        6: {
            "name": "Weak Cryptography",
            "cwe_id": "CWE-327",
            "cwe_name": "Use of a Broken or Risky Cryptographic Algorithm",
            "owasp": "A02:2021 — Cryptographic Failures",
            "severity": "medium",
            "description": (
                "Using broken or weak cryptographic algorithms (MD5, SHA1, DES, RC4) "
                "or using strong algorithms incorrectly (ECB mode, no IV/nonce, "
                "insufficient key size) can expose encrypted data to attackers."
            ),
            "impact": (
                "Data exposure, credential cracking, man-in-the-middle attacks, "
                "compliance violations."
            ),
            "remediation": [
                "Use modern algorithms: AES-256-GCM, ChaCha20-Poly1305",
                "Use bcrypt/scrypt/Argon2 for password hashing",
                "Use TLS 1.2+ for data in transit",
                "Generate unique IVs/nonces for each encryption operation",
                "Follow NIST guidelines for key lengths and algorithms",
            ],
        },
        7: {
            "name": "Buffer Overflow",
            "cwe_id": "CWE-120",
            "cwe_name": "Buffer Copy without Checking Size of Input",
            "owasp": "A06:2021 — Vulnerable and Outdated Components",
            "severity": "critical",
            "description": (
                "Buffer overflow occurs when a program writes data beyond the "
                "boundaries of a buffer. This can corrupt memory, cause crashes, "
                "or allow execution of arbitrary code."
            ),
            "impact": (
                "Remote code execution, denial of service, "
                "privilege escalation, data corruption."
            ),
            "remediation": [
                "Use bounded string functions (strncpy, snprintf, fgets)",
                "Enable compiler protections (ASLR, stack canaries, DEP/NX)",
                "Use memory-safe languages (Rust, Go, Java) where possible",
                "Validate all buffer sizes before copy operations",
                "Use static analysis tools to detect buffer issues",
            ],
        },
        8: {
            "name": "Server-Side Request Forgery (SSRF)",
            "cwe_id": "CWE-918",
            "cwe_name": "Server-Side Request Forgery",
            "owasp": "A10:2021 — Server-Side Request Forgery",
            "severity": "high",
            "description": (
                "SSRF occurs when a web application fetches a remote resource without "
                "validating the user-supplied URL. An attacker can coerce the application "
                "to send requests to internal services, cloud metadata endpoints, or "
                "other backend systems."
            ),
            "impact": (
                "Internal network scanning, cloud credential theft, "
                "access to internal services, data exfiltration."
            ),
            "remediation": [
                "Validate and sanitize all user-supplied URLs",
                "Implement URL allow-lists for permitted domains",
                "Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x)",
                "Disable unnecessary URL schemes (file://, gopher://, dict://)",
                "Use a proxy for outbound requests with egress filtering",
            ],
        },
        9: {
            "name": "Sensitive Data Exposure",
            "cwe_id": "CWE-200",
            "cwe_name": "Exposure of Sensitive Information to an Unauthorized Actor",
            "owasp": "A02:2021 — Cryptographic Failures",
            "severity": "high",
            "description": (
                "Sensitive data exposure occurs when an application fails to adequately "
                "protect sensitive information such as credentials, personal data, "
                "financial information, or health records from unauthorized access."
            ),
            "impact": (
                "Data breach, regulatory penalties (GDPR, PCI-DSS), "
                "identity theft, financial fraud."
            ),
            "remediation": [
                "Minimize data exposure — only return necessary fields in APIs",
                "Implement proper access controls on sensitive endpoints",
                "Use generic error messages; never expose stack traces or internals",
                "Encrypt sensitive data at rest and in transit",
                "Implement proper logging without recording sensitive data",
            ],
        },
        10: {
            "name": "Insecure Randomness",
            "cwe_id": "CWE-330",
            "cwe_name": "Use of Insufficiently Random Values",
            "owasp": "A02:2021 — Cryptographic Failures",
            "severity": "medium",
            "description": (
                "Using predictable random number generators (e.g., Math.random(), "
                "random module) for security-sensitive operations such as token "
                "generation, password reset codes, or session IDs makes the values "
                "guessable by attackers."
            ),
            "impact": (
                "Session hijacking, token prediction, "
                "authentication bypass, brute-force attacks."
            ),
            "remediation": [
                "Use cryptographically secure RNG (secrets, crypto.randomBytes, SecureRandom)",
                "Never use Math.random() or random module for security tokens",
                "Ensure sufficient entropy in generated values (minimum 128 bits)",
                "Use secure token generation libraries",
                "Test randomness quality of generated values",
            ],
        },
    }

    @classmethod
    def get_info(cls, vuln_id: int) -> dict:
        """Get full vulnerability information by class ID."""
        return cls.VULNERABILITY_DATABASE.get(vuln_id, {})

    @classmethod
    def get_cwe(cls, vuln_id: int) -> str:
        """Get CWE ID for a vulnerability class."""
        info = cls.get_info(vuln_id)
        return info.get("cwe_id", "Unknown")

    @classmethod
    def get_owasp(cls, vuln_id: int) -> str:
        """Get OWASP category for a vulnerability class."""
        info = cls.get_info(vuln_id)
        return info.get("owasp", "Unknown")

    @classmethod
    def get_severity(cls, vuln_id: int) -> str:
        """Get base severity for a vulnerability class."""
        info = cls.get_info(vuln_id)
        return info.get("severity", "medium")

    @classmethod
    def get_remediation(cls, vuln_id: int) -> list[str]:
        """Get remediation steps for a vulnerability class."""
        info = cls.get_info(vuln_id)
        return info.get("remediation", [])

    @classmethod
    def get_all_classes(cls) -> dict[int, str]:
        """Get mapping of all vulnerability class IDs to names."""
        return {k: v["name"] for k, v in cls.VULNERABILITY_DATABASE.items()}
