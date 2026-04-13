import os
import re

class BinaryInspector:
    """Inspects compiled binaries for potential vulnerabilities."""

    def __init__(self):
        pass

    def inspect(self, filepath: str) -> list[dict]:
        """
        Inspect a binary file for embedded strings and basic issues.
        """
        findings = []

        if not filepath:
            return findings

        try:
            with open(filepath, 'rb') as f:
                # Read just enough to get strings without loading massive binaries into memory
                content = f.read(1024 * 1024 * 5) # Read up to 5MB

            # Quick check if it's actually binary or just text
            if b'\0' in content[:1024] or filepath.endswith(('.pyc', '.so', '.dll', '.exe', '.bin', '.class')):
                # Find sequences of 4 or more printable ASCII characters
                ascii_strings = re.findall(b'[ -~]{4,}', content)
                strings = [s.decode('ascii', errors='ignore') for s in ascii_strings]

                # Look for common hardcoded secrets or patterns
                for s in strings:
                    s_lower = s.lower()
                    if "password=" in s_lower or "secret=" in s_lower or "api_key=" in s_lower or "bearer " in s_lower:
                         findings.append({
                             "vuln_class": 4, # Hardcoded credentials
                             "severity": "high",
                             "message": f"Potential hardcoded secret found in binary: '{s[:50]}...'",
                             "source": "binary_inspection"
                         })

        except Exception as e:
            pass

        return findings
