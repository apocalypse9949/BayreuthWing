import re

class HiddenRouteDetector:
    """Detects hidden or undocumented routes."""

    def __init__(self):
        pass

    def detect(self, code: str, language: str) -> list[dict]:
        """
        Analyze code for hidden routes (e.g. debug endpoints left in production).
        """
        findings = []

        # Look for conditional routes or debug flags
        patterns = [
            (r'if\s+(?:DEBUG|is_debug|debug_mode|TESTING).*?:.*?(route|endpoint|path)', "Hidden route protected only by debug/testing flag"),
            (r'x-custom-debug-header', "Hidden route triggered by custom header"),
            (r'(?:test|dev|debug|internal|admin)_api', "Hidden/Internal API route naming convention detected")
        ]

        for pattern, message in patterns:
            # Performance optimization: Track line numbers incrementally
            last_idx = 0
            current_line = 1
            for match in re.finditer(pattern, code, re.IGNORECASE | re.DOTALL):
                current_line += code.count("\n", last_idx, match.start())
                last_idx = match.start()
                findings.append({
                     "vuln_class": 9,
                     "severity": "high",
                     "line": current_line,
                     "message": f"Hidden route/logic detected: {message}",
                     "source": "hidden_route_detection"
                 })

        return findings
