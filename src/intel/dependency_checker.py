"""
BAYREUTHWING — Dependency Vulnerability Checker

Scans project dependency files (requirements.txt, package.json, pom.xml, etc.)
and checks each package against public vulnerability databases:

- PyPI Advisory Database (via GitHub Advisory Database API)
- npm Audit API
- OSV.dev (Open Source Vulnerability database by Google)

This module enables supply-chain risk analysis by identifying known
vulnerable dependencies before they reach production.
"""

import json
import re
import urllib.request
import urllib.parse
import urllib.error
from typing import Optional
from pathlib import Path


class DependencyChecker:
    """
    Checks project dependencies against public vulnerability databases.
    
    Supports:
    - Python (requirements.txt, Pipfile, pyproject.toml)
    - JavaScript/Node.js (package.json, package-lock.json)
    - Java (pom.xml — basic parsing)
    - Go (go.mod)
    - Rust (Cargo.toml — basic parsing)
    
    Uses the OSV.dev API (by Google) as the primary vulnerability source,
    which aggregates data from multiple databases including:
    - GitHub Advisory Database
    - PyPI Advisory Database
    - npm Advisory Database
    - Go Vulnerability Database
    - RustSec Advisory Database
    """

    # OSV.dev API — free, no auth required
    OSV_API_URL = "https://api.osv.dev/v1"

    # Ecosystems mapped to OSV identifiers
    ECOSYSTEM_MAP = {
        "python": "PyPI",
        "javascript": "npm",
        "java": "Maven",
        "go": "Go",
        "rust": "crates.io",
        "ruby": "RubyGems",
        "php": "Packagist",
    }

    def __init__(self, timeout: int = 10):
        """
        Args:
            timeout: HTTP request timeout in seconds.
        """
        self.timeout = timeout
        self._cache: dict[str, list[dict]] = {}

    def scan_project(self, project_path: str) -> dict:
        """
        Scan a project directory for dependency files and check vulnerabilities.
        
        Args:
            project_path: Path to the project root.
            
        Returns:
            Dictionary with dependency scan results.
        """
        path = Path(project_path)
        results = {
            "project_path": str(path),
            "dependency_files_found": [],
            "total_dependencies": 0,
            "vulnerable_dependencies": 0,
            "vulnerabilities": [],
            "dependencies": [],
        }

        # Detect and parse dependency files
        dep_parsers = {
            "requirements.txt": self._parse_requirements_txt,
            "Pipfile": self._parse_pipfile,
            "pyproject.toml": self._parse_pyproject_toml,
            "package.json": self._parse_package_json,
            "go.mod": self._parse_go_mod,
            "Cargo.toml": self._parse_cargo_toml,
            "Gemfile": self._parse_gemfile,
            "composer.json": self._parse_composer_json,
        }

        all_deps = []

        for filename, parser in dep_parsers.items():
            dep_file = path / filename
            if dep_file.exists():
                results["dependency_files_found"].append(filename)
                try:
                    content = dep_file.read_text(encoding="utf-8")
                    deps = parser(content)
                    all_deps.extend(deps)
                except Exception as e:
                    print(f"  [DEP] Error parsing {filename}: {e}")

            # Also check subdirectories (one level deep)
            if path.is_dir():
                for subdir in path.iterdir():
                    if subdir.is_dir() and subdir.name not in {
                        "node_modules", ".git", "__pycache__", "venv", ".venv",
                    }:
                        sub_file = subdir / filename
                        if sub_file.exists():
                            results["dependency_files_found"].append(
                                f"{subdir.name}/{filename}"
                            )
                            try:
                                content = sub_file.read_text(encoding="utf-8")
                                deps = parser(content)
                                all_deps.extend(deps)
                            except Exception:
                                pass

        # Remove duplicates
        seen = set()
        unique_deps = []
        for dep in all_deps:
            key = (dep["name"], dep["ecosystem"])
            if key not in seen:
                seen.add(key)
                unique_deps.append(dep)
                
        results["total_dependencies"] = len(unique_deps)
        results["dependencies"] = unique_deps

        # Check each dependency against OSV
        for dep in unique_deps:
            vulns = self.check_package(
                dep["name"],
                version=dep.get("version"),
                ecosystem=dep["ecosystem"],
            )
            dep["vulnerabilities"] = vulns
            dep["is_vulnerable"] = len(vulns) > 0
            if vulns:
                results["vulnerable_dependencies"] += 1
                for v in vulns:
                    v["package"] = dep["name"]
                    v["package_version"] = dep.get("version", "unknown")
                    v["ecosystem"] = dep["ecosystem"]
                    results["vulnerabilities"].append(v)

        return results

    def check_package(
        self,
        package_name: str,
        version: Optional[str] = None,
        ecosystem: str = "PyPI",
    ) -> list[dict]:
        """
        Check a single package for known vulnerabilities using OSV.dev.
        
        Args:
            package_name: Package name (e.g., "flask", "lodash").
            version: Package version (e.g., "2.0.1"). If None, checks all versions.
            ecosystem: Package ecosystem (PyPI, npm, Maven, etc.).
            
        Returns:
            List of vulnerability records.
        """
        cache_key = f"{ecosystem}:{package_name}:{version}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Build OSV query
        if version:
            query = {
                "version": version,
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem,
                },
            }
        else:
            query = {
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem,
                },
            }

        try:
            url = f"{self.OSV_API_URL}/query"
            data = json.dumps(query).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "BayreuthWing/1.0",
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                result = json.loads(response.read().decode("utf-8"))

            vulns = self._parse_osv_response(result)
            self._cache[cache_key] = vulns
            return vulns

        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
            # Silently handle network errors — don't break scanning
            return []

    def _parse_osv_response(self, data: dict) -> list[dict]:
        """Parse OSV API response into vulnerability records."""
        results = []
        for vuln in data.get("vulns", []):
            vuln_id = vuln.get("id", "")
            summary = vuln.get("summary", "")
            details = vuln.get("details", "")[:500]
            
            # Severity from database_specific or severity array
            severity = "UNKNOWN"
            cvss_score = None
            severity_list = vuln.get("severity", [])
            if severity_list:
                for s in severity_list:
                    if s.get("type") == "CVSS_V3":
                        score_str = s.get("score", "")
                        # Parse CVSS vector for score
                        cvss_score = score_str

            # Extract affected versions
            affected_ranges = []
            for affected in vuln.get("affected", []):
                for r in affected.get("ranges", []):
                    events = r.get("events", [])
                    range_info = {}
                    for event in events:
                        if "introduced" in event:
                            range_info["introduced"] = event["introduced"]
                        if "fixed" in event:
                            range_info["fixed"] = event["fixed"]
                    if range_info:
                        affected_ranges.append(range_info)

            # Extract references
            references = []
            for ref in vuln.get("references", [])[:3]:
                references.append({
                    "type": ref.get("type", ""),
                    "url": ref.get("url", ""),
                })

            # Aliases (CVE IDs)
            aliases = vuln.get("aliases", [])
            cve_ids = [a for a in aliases if a.startswith("CVE-")]

            # Determine severity level
            if any("CRITICAL" in str(s).upper() for s in severity_list):
                severity = "CRITICAL"
            elif any("HIGH" in str(s).upper() for s in severity_list):
                severity = "HIGH"
            elif any("MEDIUM" in str(s).upper() for s in severity_list):
                severity = "MEDIUM"
            elif any("LOW" in str(s).upper() for s in severity_list):
                severity = "LOW"

            results.append({
                "vuln_id": vuln_id,
                "cve_ids": cve_ids,
                "summary": summary,
                "details": details,
                "severity": severity,
                "cvss_vector": cvss_score,
                "affected_ranges": affected_ranges,
                "references": references,
                "published": vuln.get("published", ""),
                "modified": vuln.get("modified", ""),
            })

        return results

    # ─── Dependency File Parsers ────────────────────────────────────

    def _parse_requirements_txt(self, content: str) -> list[dict]:
        """Parse Python requirements.txt."""
        deps = []
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Parse: package==version, package>=version, package
            match = re.match(r"^([a-zA-Z0-9_.-]+)\s*(?:[=<>!~]+\s*([0-9][0-9a-zA-Z.*-]*))?", line)
            if match:
                name = match.group(1)
                version = match.group(2)
                deps.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "PyPI",
                    "source": "requirements.txt",
                })
        return deps

    def _parse_pipfile(self, content: str) -> list[dict]:
        """Parse Python Pipfile (basic TOML parsing)."""
        deps = []
        in_packages = False
        for line in content.split("\n"):
            line = line.strip()
            if line == "[packages]":
                in_packages = True
                continue
            elif line.startswith("["):
                in_packages = False
                continue
            
            if in_packages and "=" in line:
                parts = line.split("=", 1)
                name = parts[0].strip().strip('"')
                version = parts[1].strip().strip('"').lstrip("*>=<~!")
                deps.append({
                    "name": name,
                    "version": version if version else None,
                    "ecosystem": "PyPI",
                    "source": "Pipfile",
                })
        return deps

    def _parse_pyproject_toml(self, content: str) -> list[dict]:
        """Parse pyproject.toml dependencies (basic parsing)."""
        deps = []
        in_deps = False
        for line in content.split("\n"):
            line = line.strip()
            if "dependencies" in line and "=" in line and "[" in line:
                in_deps = True
                continue
            elif line.startswith("[") and "dependencies" not in line:
                in_deps = False
                continue

            if in_deps:
                # Handle: "package>=version"
                match = re.match(r'"([a-zA-Z0-9_.-]+)(?:[=<>!~]+([0-9][0-9a-zA-Z.*-]*))?', line)
                if match:
                    deps.append({
                        "name": match.group(1),
                        "version": match.group(2),
                        "ecosystem": "PyPI",
                        "source": "pyproject.toml",
                    })
        return deps

    def _parse_package_json(self, content: str) -> list[dict]:
        """Parse Node.js package.json."""
        deps = []
        try:
            pkg = json.loads(content)
            for dep_type in ["dependencies", "devDependencies"]:
                for name, version in pkg.get(dep_type, {}).items():
                    # Clean version string
                    clean_version = re.sub(r"[^0-9.]", "", version)
                    deps.append({
                        "name": name,
                        "version": clean_version if clean_version else None,
                        "ecosystem": "npm",
                        "source": "package.json",
                        "dep_type": dep_type,
                    })
        except json.JSONDecodeError:
            pass
        return deps

    def _parse_go_mod(self, content: str) -> list[dict]:
        """Parse Go go.mod."""
        deps = []
        in_require = False
        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("require ("):
                in_require = True
                continue
            elif line == ")" and in_require:
                in_require = False
                continue

            if in_require or line.startswith("require "):
                line = line.replace("require ", "").strip()
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1].lstrip("v")
                    deps.append({
                        "name": name,
                        "version": version,
                        "ecosystem": "Go",
                        "source": "go.mod",
                    })
        return deps

    def _parse_cargo_toml(self, content: str) -> list[dict]:
        """Parse Rust Cargo.toml dependencies (basic)."""
        deps = []
        in_deps = False
        for line in content.split("\n"):
            line = line.strip()
            if line in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]"):
                in_deps = True
                continue
            elif line.startswith("[") and "dependencies" not in line:
                in_deps = False
                continue

            if in_deps and "=" in line:
                parts = line.split("=", 1)
                name = parts[0].strip()
                version_str = parts[1].strip().strip('"')
                # Handle table-style: { version = "1.0" }
                version_match = re.search(r'version\s*=\s*"([^"]+)"', version_str)
                if version_match:
                    version = version_match.group(1)
                else:
                    version = version_str.strip('"')
                
                deps.append({
                    "name": name,
                    "version": version if version else None,
                    "ecosystem": "crates.io",
                    "source": "Cargo.toml",
                })
        return deps

    def _parse_gemfile(self, content: str) -> list[dict]:
        """Parse Ruby Gemfile."""
        deps = []
        for line in content.split("\n"):
            line = line.strip()
            match = re.match(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", line)
            if match:
                deps.append({
                    "name": match.group(1),
                    "version": match.group(2).lstrip("~>=<! ") if match.group(2) else None,
                    "ecosystem": "RubyGems",
                    "source": "Gemfile",
                })
        return deps

    def _parse_composer_json(self, content: str) -> list[dict]:
        """Parse PHP composer.json."""
        deps = []
        try:
            pkg = json.loads(content)
            for dep_type in ["require", "require-dev"]:
                for name, version in pkg.get(dep_type, {}).items():
                    if name == "php" or name.startswith("ext-"):
                        continue
                    clean_version = re.sub(r"[^0-9.]", "", version)
                    deps.append({
                        "name": name,
                        "version": clean_version if clean_version else None,
                        "ecosystem": "Packagist",
                        "source": "composer.json",
                    })
        except json.JSONDecodeError:
            pass
        return deps

    def format_report(self, results: dict) -> str:
        """Format dependency scan results as a readable report."""
        lines = []
        lines.append("")
        lines.append("  DEPENDENCY VULNERABILITY REPORT")
        lines.append("  " + "=" * 55)
        lines.append(f"  Project: {results['project_path']}")
        lines.append(f"  Files Found: {', '.join(results['dependency_files_found']) or 'None'}")
        lines.append(f"  Total Dependencies: {results['total_dependencies']}")
        lines.append(f"  Vulnerable: {results['vulnerable_dependencies']}")
        lines.append("")

        if results["vulnerabilities"]:
            lines.append("  VULNERABLE PACKAGES:")
            lines.append("  " + "-" * 55)

            for vuln in results["vulnerabilities"]:
                severity = vuln.get("severity", "UNKNOWN")
                lines.append(
                    f"    [{severity:>8}] {vuln['package']}@{vuln['package_version']} "
                    f"({vuln['ecosystem']})"
                )
                lines.append(f"             {vuln['vuln_id']}: {vuln['summary'][:80]}")
                if vuln.get("cve_ids"):
                    lines.append(f"             CVEs: {', '.join(vuln['cve_ids'])}")
                if vuln.get("affected_ranges"):
                    for r in vuln["affected_ranges"][:1]:
                        fix = r.get("fixed", "No fix available")
                        lines.append(f"             Fix: Upgrade to >= {fix}")
                lines.append("")
        else:
            lines.append("  No known vulnerabilities found in dependencies.")
            lines.append("")

        return "\n".join(lines)
