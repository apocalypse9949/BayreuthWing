import re

class EndpointDiscoverer:
    """Discovers API endpoints and routes from source code."""

    def __init__(self):
        pass

    def discover(self, code: str, language: str) -> list[dict]:
        """
        Extract potential endpoints from code.
        """
        findings = []

        # Simple regex to find common route definitions
        route_patterns = [
            r'@app\.route\([\'"]([^\'"]+)[\'"]\)', # Flask
            r'app\.(?:get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]\)', # Express
            r'@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\([\'"]([^\'"]+)[\'"]\)' # Spring
        ]

        for pattern in route_patterns:
            last_idx = 0
            current_line = 1
            for match in re.finditer(pattern, code):
                endpoint = match.group(1)
                # ⚡ Bolt: Prevent O(N^2) line counting performance bottleneck
                current_line += code.count("\n", last_idx, match.start())
                last_idx = match.start()

                # Check for potentially sensitive endpoints
                if "admin" in endpoint.lower() or "internal" in endpoint.lower() or "debug" in endpoint.lower():
                     findings.append({
                         "vuln_class": 9,
                         "severity": "medium",
                         "line": current_line,
                         "message": f"Potentially sensitive endpoint discovered: {endpoint}",
                         "source": "endpoint_discovery"
                     })

        return findings
