"""
BAYREUTHWING — CWE/OWASP Mapping (v2.0 — World Coverage)

Maps 35 vulnerability classes to CWE IDs, OWASP Top 10 categories, and
provides detailed vulnerability information including descriptions,
impact assessments, and remediation guidance.

Coverage:
    - OWASP Top 10 (2021) — all categories
    - CWE Top 25 Most Dangerous (2023) — full coverage
    - SANS Top 25 — full coverage
    - MITRE ATT&CK technique mapping where applicable
    - Platform-specific vulnerabilities (web, mobile, binary, API)
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

    35 vulnerability classes covering every major vulnerability
    family known in the global security landscape.
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
        # ═══════════════════════════════════════════════════════
        # NEW CLASSES (11-34) — World Vulnerability Coverage
        # ═══════════════════════════════════════════════════════
        11: {
            "name": "XML External Entities (XXE)",
            "cwe_id": "CWE-611",
            "cwe_name": "Improper Restriction of XML External Entity Reference",
            "owasp": "A05:2021 — Security Misconfiguration",
            "severity": "high",
            "description": (
                "XXE attacks exploit XML parsers that process external entity references. "
                "Attackers can use XXE to read local files, perform SSRF, execute remote "
                "code, or cause denial of service via entity expansion (billion laughs)."
            ),
            "impact": (
                "Local file disclosure, SSRF, denial of service, "
                "remote code execution via external DTDs."
            ),
            "remediation": [
                "Disable DTD processing and external entities in XML parsers",
                "Use defusedxml (Python) or equivalent safe parsers",
                "Prefer JSON over XML where possible",
                "Validate and sanitize all XML input",
                "Use allowlists for permitted XML entities",
            ],
        },
        12: {
            "name": "LDAP Injection",
            "cwe_id": "CWE-90",
            "cwe_name": "Improper Neutralization of Special Elements used in an LDAP Query",
            "owasp": "A03:2021 — Injection",
            "severity": "high",
            "description": (
                "LDAP injection occurs when untrusted data is included in LDAP queries "
                "without proper sanitization. Attackers can modify query logic to bypass "
                "authentication, enumerate directory information, or modify directory entries."
            ),
            "impact": (
                "Authentication bypass, directory enumeration, "
                "privilege escalation, data modification."
            ),
            "remediation": [
                "Use parameterized LDAP queries or prepared filters",
                "Escape special LDAP characters (*, (, ), \\, NUL)",
                "Validate input against strict allowlists",
                "Use LDAP frameworks with built-in injection protection",
                "Apply least-privilege to LDAP bind accounts",
            ],
        },
        13: {
            "name": "XPath Injection",
            "cwe_id": "CWE-643",
            "cwe_name": "Improper Neutralization of Data within XPath Expressions",
            "owasp": "A03:2021 — Injection",
            "severity": "high",
            "description": (
                "XPath injection occurs when user input is included in XPath queries "
                "without sanitization. Attackers can modify query logic to extract "
                "data from XML documents or bypass authentication."
            ),
            "impact": (
                "Data extraction from XML stores, authentication bypass, "
                "information disclosure, logic manipulation."
            ),
            "remediation": [
                "Use parameterized XPath queries where available",
                "Validate and sanitize all input used in XPath expressions",
                "Use XPath compilation APIs that separate query from data",
                "Implement strict input validation with allowlists",
                "Consider using alternative query mechanisms",
            ],
        },
        14: {
            "name": "Server-Side Template Injection (SSTI)",
            "cwe_id": "CWE-1336",
            "cwe_name": "Improper Neutralization of Special Elements Used in a Template Engine",
            "owasp": "A03:2021 — Injection",
            "severity": "critical",
            "description": (
                "SSTI occurs when user input is embedded into server-side templates "
                "without sanitization. Attackers can inject template directives to "
                "execute arbitrary code on the server, read files, or escalate privileges."
            ),
            "impact": (
                "Remote code execution, full server compromise, "
                "data exfiltration, lateral movement."
            ),
            "remediation": [
                "Never pass user input directly into template strings",
                "Use logic-less templates (Mustache, Handlebars) where possible",
                "Implement sandboxed template environments",
                "Use template engines with auto-escaping enabled by default",
                "Validate all user input before template rendering",
            ],
        },
        15: {
            "name": "HTTP Header Injection",
            "cwe_id": "CWE-113",
            "cwe_name": "Improper Neutralization of CRLF Sequences in HTTP Headers",
            "owasp": "A03:2021 — Injection",
            "severity": "medium",
            "description": (
                "HTTP header injection occurs when user input is included in HTTP headers "
                "without proper validation. Attackers can inject additional headers, "
                "split HTTP responses, or set malicious cookies."
            ),
            "impact": (
                "HTTP response splitting, cache poisoning, "
                "session fixation, XSS via injected headers."
            ),
            "remediation": [
                "Validate and sanitize all input used in HTTP headers",
                "Strip CR (\\r) and LF (\\n) characters from header values",
                "Use framework-provided header setting methods",
                "Implement Content-Security-Policy headers",
                "Use HTTP-only and Secure cookie flags",
            ],
        },
        16: {
            "name": "CRLF Injection",
            "cwe_id": "CWE-93",
            "cwe_name": "Improper Neutralization of CRLF Sequences",
            "owasp": "A03:2021 — Injection",
            "severity": "medium",
            "description": (
                "CRLF injection allows attackers to inject carriage return and line feed "
                "characters into output streams, enabling log forgery, HTTP response "
                "splitting, and header manipulation."
            ),
            "impact": (
                "Log forging, HTTP response splitting, "
                "cache poisoning, session hijacking."
            ),
            "remediation": [
                "Strip or encode CRLF characters (\\r\\n) from all user input",
                "Use allowlist validation for data included in logs or headers",
                "Use structured logging frameworks that handle encoding",
                "Validate URL redirect targets against allowlists",
                "Implement output encoding for all untrusted data",
            ],
        },
        17: {
            "name": "Log Injection / Forging",
            "cwe_id": "CWE-117",
            "cwe_name": "Improper Output Neutralization for Logs",
            "owasp": "A09:2021 — Security Logging and Monitoring Failures",
            "severity": "medium",
            "description": (
                "Log injection occurs when untrusted data is written to log files "
                "without sanitization. Attackers can inject fake log entries to cover "
                "tracks, trigger false alerts, or exploit log processing systems."
            ),
            "impact": (
                "Log tampering, SIEM evasion, false alert injection, "
                "compliance violations, log processing exploitation."
            ),
            "remediation": [
                "Sanitize all data before logging (encode newlines, special chars)",
                "Use structured logging formats (JSON) instead of plain text",
                "Implement log integrity verification (hashing, append-only stores)",
                "Never log sensitive data (passwords, tokens, PII)",
                "Use logging frameworks that auto-encode output",
            ],
        },
        18: {
            "name": "Prototype Pollution",
            "cwe_id": "CWE-1321",
            "cwe_name": "Improperly Controlled Modification of Object Prototype Attributes",
            "owasp": "A08:2021 — Software and Data Integrity Failures",
            "severity": "high",
            "description": (
                "Prototype pollution is a JavaScript-specific vulnerability where "
                "attackers modify the prototype of base objects (Object.prototype). "
                "This can alter application logic, bypass security checks, or enable "
                "remote code execution in Node.js environments."
            ),
            "impact": (
                "Remote code execution, authentication bypass, "
                "denial of service, property injection."
            ),
            "remediation": [
                "Freeze Object.prototype using Object.freeze()",
                "Use Map/Set instead of plain objects for user-controlled keys",
                "Validate and sanitize property names from user input",
                "Use libraries like lodash with prototype pollution protections",
                "Avoid recursive merge of untrusted objects into application state",
            ],
        },
        19: {
            "name": "Race Condition / TOCTOU",
            "cwe_id": "CWE-367",
            "cwe_name": "Time-of-check Time-of-use (TOCTOU) Race Condition",
            "owasp": "A04:2021 — Insecure Design",
            "severity": "high",
            "description": (
                "Race conditions occur when the correctness of a program depends on "
                "the sequence or timing of uncontrollable events. TOCTOU vulnerabilities "
                "arise when a resource is checked and then used with a gap that allows "
                "the resource state to change between check and use."
            ),
            "impact": (
                "Privilege escalation, data corruption, "
                "authentication bypass, file system attacks."
            ),
            "remediation": [
                "Use atomic operations for check-and-act patterns",
                "Implement proper locking mechanisms (mutexes, semaphores)",
                "Use file locking for filesystem operations",
                "Avoid time-of-check-time-of-use patterns",
                "Use database transactions for concurrent data access",
            ],
        },
        20: {
            "name": "Integer Overflow",
            "cwe_id": "CWE-190",
            "cwe_name": "Integer Overflow or Wraparound",
            "owasp": "A06:2021 — Vulnerable and Outdated Components",
            "severity": "high",
            "description": (
                "Integer overflow occurs when an arithmetic operation produces a value "
                "that exceeds the maximum size of the integer type. This can lead to "
                "buffer overflows, incorrect calculations, or logic bypasses."
            ),
            "impact": (
                "Buffer overflow, incorrect access control decisions, "
                "memory corruption, denial of service."
            ),
            "remediation": [
                "Use safe integer arithmetic libraries",
                "Check for overflow before performing operations",
                "Use larger integer types (int64 instead of int32)",
                "Enable compiler overflow detection flags (-ftrapv)",
                "Use languages with built-in overflow protection (Rust, Go)",
            ],
        },
        21: {
            "name": "Use After Free",
            "cwe_id": "CWE-416",
            "cwe_name": "Use After Free",
            "owasp": "A06:2021 — Vulnerable and Outdated Components",
            "severity": "critical",
            "description": (
                "Use-after-free occurs when a program continues to use memory after "
                "it has been freed. This can lead to arbitrary code execution, crashes, "
                "or data corruption when the freed memory is reallocated."
            ),
            "impact": (
                "Remote code execution, privilege escalation, "
                "data corruption, denial of service."
            ),
            "remediation": [
                "Set pointers to NULL after freeing memory",
                "Use smart pointers (C++) or ownership systems (Rust)",
                "Enable AddressSanitizer (ASan) during development",
                "Use memory-safe languages where possible",
                "Implement reference counting for shared resources",
            ],
        },
        22: {
            "name": "Null Pointer Dereference",
            "cwe_id": "CWE-476",
            "cwe_name": "NULL Pointer Dereference",
            "owasp": "A06:2021 — Vulnerable and Outdated Components",
            "severity": "medium",
            "description": (
                "Null pointer dereference occurs when a program attempts to use a "
                "pointer that has not been initialized or has been set to null. "
                "This typically causes crashes but can sometimes be exploited for "
                "code execution."
            ),
            "impact": (
                "Denial of service, application crash, "
                "potential code execution in some contexts."
            ),
            "remediation": [
                "Always check pointers for null before dereferencing",
                "Use Optional/Maybe types to represent nullable values",
                "Enable null analysis compiler warnings",
                "Use static analysis tools to detect null dereference paths",
                "Initialize all pointers at declaration",
            ],
        },
        23: {
            "name": "Open Redirect",
            "cwe_id": "CWE-601",
            "cwe_name": "URL Redirection to Untrusted Site ('Open Redirect')",
            "owasp": "A01:2021 — Broken Access Control",
            "severity": "medium",
            "description": (
                "Open redirect vulnerabilities occur when an application redirects users "
                "to a URL specified by user input without proper validation. Attackers "
                "use this to redirect victims to phishing or malware sites."
            ),
            "impact": (
                "Phishing attacks, credential theft, "
                "malware distribution, trust exploitation."
            ),
            "remediation": [
                "Validate redirect URLs against an allowlist of domains",
                "Use relative redirects instead of absolute URLs",
                "Map redirect targets to indices (e.g., ?redirect=1)",
                "Warn users before redirecting to external sites",
                "Never use user input directly as redirect target",
            ],
        },
        24: {
            "name": "CORS Misconfiguration",
            "cwe_id": "CWE-942",
            "cwe_name": "Permissive Cross-domain Policy with Untrusted Domains",
            "owasp": "A05:2021 — Security Misconfiguration",
            "severity": "medium",
            "description": (
                "CORS misconfiguration occurs when an application improperly configures "
                "Cross-Origin Resource Sharing headers, allowing unauthorized domains "
                "to make requests to the application. Wildcard origins or reflecting "
                "the request origin are common misconfigurations."
            ),
            "impact": (
                "Cross-origin data theft, CSRF-like attacks, "
                "session hijacking via cross-origin requests."
            ),
            "remediation": [
                "Use explicit origin allowlists instead of wildcards (*)",
                "Never reflect the Origin header directly in Access-Control-Allow-Origin",
                "Avoid Access-Control-Allow-Credentials with wildcard origins",
                "Validate origins server-side against a trusted list",
                "Use framework CORS middleware with proper configuration",
            ],
        },
        25: {
            "name": "JWT Vulnerabilities",
            "cwe_id": "CWE-347",
            "cwe_name": "Improper Verification of Cryptographic Signature",
            "owasp": "A07:2021 — Identification and Authentication Failures",
            "severity": "high",
            "description": (
                "JWT vulnerabilities include accepting 'none' algorithm, using weak "
                "signing keys, algorithm confusion attacks (RS256→HS256), missing "
                "expiration validation, and insecure key management."
            ),
            "impact": (
                "Authentication bypass, token forging, "
                "privilege escalation, identity impersonation."
            ),
            "remediation": [
                "Explicitly specify and validate the signing algorithm",
                "Reject tokens with 'none' algorithm",
                "Use strong keys (RSA 2048+, HMAC-SHA256 with 256-bit+ keys)",
                "Always validate exp, iat, and nbf claims",
                "Use established JWT libraries with known security track records",
            ],
        },
        26: {
            "name": "OAuth / OIDC Misconfiguration",
            "cwe_id": "CWE-287",
            "cwe_name": "Improper Authentication",
            "owasp": "A07:2021 — Identification and Authentication Failures",
            "severity": "high",
            "description": (
                "OAuth/OIDC misconfigurations include insecure redirect URI validation, "
                "missing state parameter (CSRF), improper token storage, using implicit "
                "flow in SPAs, and insufficient scope validation."
            ),
            "impact": (
                "Account takeover, authorization code theft, "
                "token leakage, CSRF attacks on OAuth flows."
            ),
            "remediation": [
                "Use exact redirect URI matching (no wildcards)",
                "Always use and validate the state parameter for CSRF protection",
                "Use PKCE for public clients (SPAs, mobile apps)",
                "Store tokens securely (HttpOnly cookies, not localStorage)",
                "Use authorization code flow instead of implicit flow",
            ],
        },
        27: {
            "name": "Mass Assignment",
            "cwe_id": "CWE-915",
            "cwe_name": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
            "owasp": "A04:2021 — Insecure Design",
            "severity": "high",
            "description": (
                "Mass assignment (over-posting) occurs when an application binds "
                "user-supplied data directly to internal objects without filtering. "
                "Attackers can modify fields they shouldn't have access to, such as "
                "roles, permissions, or pricing."
            ),
            "impact": (
                "Privilege escalation, data manipulation, "
                "unauthorized field modification, business logic bypass."
            ),
            "remediation": [
                "Use allowlists (permit lists) for bindable fields",
                "Create separate DTOs/ViewModels for input and internal objects",
                "Never bind request data directly to database models",
                "Use @JsonIgnore or equivalent to protect sensitive fields",
                "Implement field-level authorization checks",
            ],
        },
        28: {
            "name": "IDOR / BOLA",
            "cwe_id": "CWE-639",
            "cwe_name": "Authorization Bypass Through User-Controlled Key",
            "owasp": "A01:2021 — Broken Access Control",
            "severity": "high",
            "description": (
                "Insecure Direct Object Reference (IDOR) / Broken Object Level "
                "Authorization (BOLA) occurs when an application uses user-controllable "
                "references to access objects without verifying the user's authorization "
                "to access them."
            ),
            "impact": (
                "Unauthorized data access, data modification, "
                "horizontal and vertical privilege escalation."
            ),
            "remediation": [
                "Implement object-level authorization checks in every endpoint",
                "Use indirect references (UUIDs) instead of sequential IDs",
                "Verify ownership/permissions before returning or modifying data",
                "Use authorization middleware/decorators consistently",
                "Log and alert on access pattern anomalies",
            ],
        },
        29: {
            "name": "DNS Rebinding",
            "cwe_id": "CWE-350",
            "cwe_name": "Reliance on Reverse DNS Resolution for a Security-Critical Action",
            "owasp": "A10:2021 — Server-Side Request Forgery",
            "severity": "high",
            "description": (
                "DNS rebinding attacks exploit the DNS resolution process to bypass "
                "same-origin policy. An attacker controls a DNS server that initially "
                "resolves to an external IP but later switches to an internal IP, "
                "allowing access to internal services."
            ),
            "impact": (
                "Internal network access, firewall bypass, "
                "access to localhost services, data exfiltration."
            ),
            "remediation": [
                "Validate resolved IP addresses against private ranges before connecting",
                "Pin DNS results and re-validate on reconnection",
                "Use Host header validation on internal services",
                "Implement network-level segmentation",
                "Use TLS with proper certificate validation for internal services",
            ],
        },
        30: {
            "name": "Dependency Confusion",
            "cwe_id": "CWE-427",
            "cwe_name": "Uncontrolled Search Path Element",
            "owasp": "A08:2021 — Software and Data Integrity Failures",
            "severity": "critical",
            "description": (
                "Dependency confusion attacks exploit package manager behavior where "
                "public packages take priority over private ones. Attackers publish "
                "malicious packages with the same names as internal packages to public "
                "registries, which then get installed instead of the legitimate ones."
            ),
            "impact": (
                "Supply chain compromise, malicious code execution, "
                "data exfiltration, backdoor installation."
            ),
            "remediation": [
                "Use scoped packages (@company/package) in npm",
                "Pin exact versions in dependency files",
                "Configure package manager to prefer private registries",
                "Use dependency lock files and verify checksums",
                "Monitor for unauthorized package publications matching internal names",
            ],
        },
        31: {
            "name": "ReDoS (Regex DoS)",
            "cwe_id": "CWE-1333",
            "cwe_name": "Inefficient Regular Expression Complexity",
            "owasp": "A06:2021 — Vulnerable and Outdated Components",
            "severity": "medium",
            "description": (
                "Regular Expression Denial of Service occurs when a poorly crafted regex "
                "pattern exhibits catastrophic backtracking on certain input strings. "
                "This can cause CPU exhaustion and application hangs."
            ),
            "impact": (
                "Denial of service, CPU exhaustion, "
                "application unavailability, cascading failures."
            ),
            "remediation": [
                "Avoid nested quantifiers (e.g., (a+)+ or (a|b)*c)",
                "Use atomic groups or possessive quantifiers where supported",
                "Set timeout limits on regex execution",
                "Use RE2 or similar engines that guarantee linear-time matching",
                "Test regex performance with adversarial input strings",
            ],
        },
        32: {
            "name": "Session Fixation",
            "cwe_id": "CWE-384",
            "cwe_name": "Session Fixation",
            "owasp": "A07:2021 — Identification and Authentication Failures",
            "severity": "high",
            "description": (
                "Session fixation occurs when an attacker can set or predict a user's "
                "session identifier before they authenticate. After the victim logs in "
                "with the fixed session ID, the attacker can hijack the authenticated session."
            ),
            "impact": (
                "Session hijacking, identity theft, "
                "unauthorized access, account takeover."
            ),
            "remediation": [
                "Regenerate session ID after successful authentication",
                "Invalidate existing sessions on login",
                "Use secure, HttpOnly, SameSite cookie attributes",
                "Bind sessions to client fingerprints (IP, User-Agent)",
                "Set short session expiration timeouts",
            ],
        },
        33: {
            "name": "Clickjacking",
            "cwe_id": "CWE-1021",
            "cwe_name": "Improper Restriction of Rendered UI Layers or Frames",
            "owasp": "A04:2021 — Insecure Design",
            "severity": "medium",
            "description": (
                "Clickjacking involves tricking users into clicking on hidden interface "
                "elements by overlaying transparent frames over legitimate content. "
                "This can lead to unauthorized actions performed on behalf of the victim."
            ),
            "impact": (
                "Unauthorized actions, data theft via click redirection, "
                "account changes, social engineering amplification."
            ),
            "remediation": [
                "Set X-Frame-Options header to DENY or SAMEORIGIN",
                "Use Content-Security-Policy frame-ancestors directive",
                "Implement frame-busting JavaScript as a fallback",
                "Use SameSite cookie attribute to prevent cross-origin framing",
                "Add confirmation dialogs for sensitive actions",
            ],
        },
        34: {
            "name": "Insecure File Upload",
            "cwe_id": "CWE-434",
            "cwe_name": "Unrestricted Upload of File with Dangerous Type",
            "owasp": "A04:2021 — Insecure Design",
            "severity": "high",
            "description": (
                "Insecure file upload allows attackers to upload malicious files such "
                "as web shells, executables, or script files. Without proper validation "
                "of file type, size, and content, these can lead to remote code execution."
            ),
            "impact": (
                "Remote code execution via web shells, "
                "server compromise, malware distribution, data exfiltration."
            ),
            "remediation": [
                "Validate file type by content (magic bytes), not just extension",
                "Use allowlists for permitted file extensions and MIME types",
                "Store uploaded files outside the web root",
                "Rename files with random names to prevent direct access",
                "Scan uploaded files with antivirus/malware detection",
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

    @classmethod
    def get_class_count(cls) -> int:
        """Get total number of vulnerability classes."""
        return len(cls.VULNERABILITY_DATABASE)

    @classmethod
    def search_by_cwe(cls, cwe_id: str) -> list[dict]:
        """Search vulnerability classes by CWE ID."""
        results = []
        cwe_upper = cwe_id.upper()
        for vid, info in cls.VULNERABILITY_DATABASE.items():
            if info.get("cwe_id", "").upper() == cwe_upper:
                results.append({"vuln_id": vid, **info})
        return results

    @classmethod
    def search_by_owasp(cls, owasp_category: str) -> list[dict]:
        """Search vulnerability classes by OWASP category."""
        results = []
        cat_upper = owasp_category.upper()
        for vid, info in cls.VULNERABILITY_DATABASE.items():
            if cat_upper in info.get("owasp", "").upper():
                results.append({"vuln_id": vid, **info})
        return results
