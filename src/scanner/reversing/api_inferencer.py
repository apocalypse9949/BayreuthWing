import re

class ApiInferencer:
    """Infers API behavior from source code or documentation."""

    def __init__(self):
        pass

    def infer(self, code: str, language: str) -> list[dict]:
        """
        Analyze code to infer API structure and potential vulnerabilities.
        """
        findings = []

        # Look for unprotected API endpoints (simple heuristic)
        if language in ["python", "javascript", "php"]:
             # Check if there are auth/authz decorators or middleware
             has_auth = "auth" in code.lower() or "login" in code.lower() or "token" in code.lower()

             if not has_auth and ("route" in code.lower() or "endpoint" in code.lower()):
                 findings.append({
                     "vuln_class": 9, # Sensitive data exposure / Broken Access Control
                     "severity": "medium",
                     "message": "API endpoint inferred without clear authentication/authorization mechanisms.",
                     "source": "api_inference"
                 })

        return findings
