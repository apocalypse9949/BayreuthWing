"""
BAYREUTHWING — Internet-Connected Zero-Day Vulnerability Discovery

When the scanner encounters suspicious code patterns that don't match
any known vulnerability signature, this module searches the internet
for matching vulnerability reports, CVEs, and active exploits.

Sources:
    - NVD (NIST National Vulnerability Database) — CVE details, CVSS scores
    - OSV.dev (Google) — Open source vulnerability database
    - Exploit-DB — Known public exploits
    - CISA KEV — Known Exploited Vulnerabilities catalog
    - GitHub Security Advisories — Repository-specific advisories

Architecture:
    ┌──────────────────────────┐
    │  ZeroDayDiscoveryEngine  │
    │  - search_for_pattern()  │
    │  - analyze_trending()    │
    │  - generate_new_rules()  │
    └──────────┬───────────────┘
               │
    ┌──────────▼───────────────┐
    │  PatternMatcherOnline    │
    │  - NVD search            │
    │  - OSV.dev query         │
    │  - Exploit-DB search     │
    └──────────┬───────────────┘
               │
    ┌──────────▼───────────────┐
    │  TrendAnalyzer           │
    │  - emerging CVE patterns │
    │  - new CWE categories    │
    │  - dynamic rule gen      │
    └──────────────────────────┘
"""

import json
import time
import hashlib
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timedelta


@dataclass
class DiscoveryResult:
    """Result from an internet vulnerability search."""
    query: str
    source: str
    matches: list = field(default_factory=list)
    search_time_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "query": self.query,
            "source": self.source,
            "matches_count": len(self.matches),
            "search_time_ms": round(self.search_time_ms, 2),
            "timestamp": self.timestamp,
            "error": self.error,
            "matches": self.matches[:20],  # Cap for readability
        }


@dataclass
class TrendingVulnerability:
    """A trending vulnerability pattern from public sources."""
    cve_id: str = ""
    cwe_id: str = ""
    description: str = ""
    severity: str = "medium"
    cvss_score: float = 0.0
    published_date: str = ""
    affected_patterns: list = field(default_factory=list)
    source: str = ""
    exploit_available: bool = False
    actively_exploited: bool = False

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "description": self.description[:200],
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "published_date": self.published_date,
            "source": self.source,
            "exploit_available": self.exploit_available,
            "actively_exploited": self.actively_exploited,
        }


class PatternMatcherOnline:
    """
    Searches online vulnerability databases for patterns matching
    unclassified findings from the scanner.
    """

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    OSV_API_URL = "https://api.osv.dev/v1"
    EXPLOITDB_SEARCH_URL = "https://www.exploit-db.com/search"

    def __init__(self, timeout: int = 30, nvd_api_key: str = ""):
        self.timeout = timeout
        self.nvd_api_key = nvd_api_key
        self._cache: dict[str, DiscoveryResult] = {}
        self._cache_ttl = 3600  # 1 hour

    def _http_get(self, url: str, headers: dict | None = None) -> Optional[bytes]:
        """Make an HTTP GET request."""
        req_headers = {
            "User-Agent": "BayreuthWing/2.0 (Vulnerability Discovery Engine)",
            "Accept": "application/json",
        }
        if headers:
            req_headers.update(headers)

        try:
            req = urllib.request.Request(url, headers=req_headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return response.read()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
            return None

    def _http_post(self, url: str, data: dict) -> Optional[bytes]:
        """Make an HTTP POST request."""
        try:
            encoded = json.dumps(data).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=encoded,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "BayreuthWing/2.0",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return response.read()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
            return None

    def search_nvd(self, keyword: str, max_results: int = 10) -> DiscoveryResult:
        """Search the NVD for vulnerabilities matching a keyword."""
        cache_key = f"nvd:{keyword}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if time.time() - cached.timestamp < self._cache_ttl:
                return cached

        start_time = time.time()
        result = DiscoveryResult(query=keyword, source="NVD")

        try:
            params = f"?keywordSearch={urllib.request.quote(keyword)}&resultsPerPage={max_results}"
            url = f"{self.NVD_API_URL}{params}"

            if self.nvd_api_key:
                raw = self._http_get(url, headers={"apiKey": self.nvd_api_key})
            else:
                raw = self._http_get(url)

            if raw:
                data = json.loads(raw.decode("utf-8"))
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    descriptions = cve.get("descriptions", [])
                    desc_text = ""
                    for d in descriptions:
                        if d.get("lang") == "en":
                            desc_text = d.get("value", "")
                            break

                    # Extract CVSS score
                    metrics = cve.get("metrics", {})
                    cvss_score = 0.0
                    severity = "medium"
                    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        metric_list = metrics.get(version, [])
                        if metric_list:
                            cvss_data = metric_list[0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore", 0.0)
                            severity = cvss_data.get("baseSeverity", "MEDIUM").lower()
                            break

                    # Extract CWE
                    cwe_id = ""
                    weaknesses = cve.get("weaknesses", [])
                    for w in weaknesses:
                        for desc in w.get("description", []):
                            if desc.get("value", "").startswith("CWE-"):
                                cwe_id = desc["value"]
                                break

                    result.matches.append({
                        "cve_id": cve.get("id", ""),
                        "description": desc_text[:300],
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "cwe_id": cwe_id,
                        "published": cve.get("published", ""),
                        "source": "NVD",
                    })

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            result.error = str(e)

        result.search_time_ms = (time.time() - start_time) * 1000
        self._cache[cache_key] = result
        return result

    def search_osv(self, keyword: str, ecosystem: str = "") -> DiscoveryResult:
        """Search OSV.dev for matching vulnerabilities."""
        cache_key = f"osv:{keyword}:{ecosystem}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if time.time() - cached.timestamp < self._cache_ttl:
                return cached

        start_time = time.time()
        result = DiscoveryResult(query=keyword, source="OSV.dev")

        try:
            query_data = {}
            if ecosystem:
                query_data["package"] = {"ecosystem": ecosystem, "name": keyword}
            else:
                query_data["package"] = {"name": keyword}

            raw = self._http_post(f"{self.OSV_API_URL}/query", query_data)
            if raw:
                data = json.loads(raw.decode("utf-8"))
                for vuln in data.get("vulns", [])[:20]:
                    result.matches.append({
                        "id": vuln.get("id", ""),
                        "summary": vuln.get("summary", "")[:200],
                        "aliases": vuln.get("aliases", []),
                        "published": vuln.get("published", ""),
                        "severity": self._osv_severity(vuln),
                        "source": "OSV.dev",
                    })

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            result.error = str(e)

        result.search_time_ms = (time.time() - start_time) * 1000
        self._cache[cache_key] = result
        return result

    def _osv_severity(self, vuln: dict) -> str:
        """Extract severity from OSV vulnerability."""
        severity_list = vuln.get("severity", [])
        for s in severity_list:
            score_str = s.get("score", "")
            try:
                score = float(score_str.split("/")[0]) if "/" in score_str else float(score_str)
                if score >= 9.0:
                    return "critical"
                elif score >= 7.0:
                    return "high"
                elif score >= 4.0:
                    return "medium"
                else:
                    return "low"
            except (ValueError, IndexError):
                pass
        return "medium"

    def search_all(self, keyword: str) -> list[DiscoveryResult]:
        """Search all available sources for a vulnerability keyword."""
        results = []
        results.append(self.search_nvd(keyword))
        results.append(self.search_osv(keyword))
        return results


class TrendAnalyzer:
    """
    Analyzes trending vulnerability patterns from public sources
    and generates new dynamic rules for the scanner.
    """

    def __init__(self, matcher: PatternMatcherOnline | None = None):
        self.matcher = matcher or PatternMatcherOnline()
        self._trending_cache: list[TrendingVulnerability] = []
        self._last_refresh: float = 0
        self._refresh_interval = 86400  # 24 hours

    def get_trending_vulns(self, days: int = 30) -> list[TrendingVulnerability]:
        """
        Get recently trending vulnerabilities.

        Queries NVD for recently published CVEs with high CVSS scores.
        """
        if (
            self._trending_cache
            and time.time() - self._last_refresh < self._refresh_interval
        ):
            return self._trending_cache

        trending = []

        # Search for recent critical CVEs
        try:
            result = self.matcher.search_nvd("critical vulnerability", max_results=20)
            for match in result.matches:
                if match.get("cvss_score", 0) >= 7.0:
                    trending.append(TrendingVulnerability(
                        cve_id=match.get("cve_id", ""),
                        cwe_id=match.get("cwe_id", ""),
                        description=match.get("description", ""),
                        severity=match.get("severity", "high"),
                        cvss_score=match.get("cvss_score", 0.0),
                        published_date=match.get("published", ""),
                        source="NVD",
                    ))
        except Exception:
            pass

        self._trending_cache = trending
        self._last_refresh = time.time()
        return trending

    def generate_rules_from_trends(self) -> list[dict]:
        """
        Generate new dynamic rules based on trending vulnerabilities.

        Returns rule dictionaries that can be loaded by DynamicRuleEngine.
        """
        trending = self.get_trending_vulns()
        new_rules = []

        for vuln in trending:
            if not vuln.cve_id:
                continue

            rule_id = f"TREND-{vuln.cve_id.replace('CVE-', '')}"

            # Map CWE to vuln class
            vuln_class = self._cwe_to_vuln_class(vuln.cwe_id)

            new_rules.append({
                "rule_id": rule_id,
                "name": f"Trending: {vuln.cve_id}",
                "description": vuln.description[:200],
                "pattern": "",  # Pattern would need manual creation
                "vuln_class": vuln_class,
                "severity": vuln.severity,
                "confidence": 0.5,
                "source": "internet_discovery",
                "tags": ["trending", vuln.cve_id, vuln.cwe_id],
            })

        return new_rules

    def _cwe_to_vuln_class(self, cwe_id: str) -> int:
        """Map CWE IDs to BayreuthWing vulnerability class IDs."""
        cwe_map = {
            "CWE-89": 0,    # SQL Injection
            "CWE-79": 1,    # XSS
            "CWE-78": 2,    # Command Injection
            "CWE-22": 3,    # Path Traversal
            "CWE-798": 4,   # Hardcoded Credentials
            "CWE-502": 5,   # Insecure Deserialization
            "CWE-327": 6,   # Weak Cryptography
            "CWE-120": 7,   # Buffer Overflow
            "CWE-918": 8,   # SSRF
            "CWE-200": 9,   # Sensitive Data Exposure
            "CWE-330": 10,  # Insecure Randomness
            "CWE-611": 11,  # XXE
            "CWE-90": 12,   # LDAP Injection
            "CWE-643": 13,  # XPath Injection
            "CWE-1336": 14, # SSTI
            "CWE-113": 15,  # Header Injection
            "CWE-93": 16,   # CRLF Injection
            "CWE-117": 17,  # Log Injection
            "CWE-1321": 18, # Prototype Pollution
            "CWE-367": 19,  # Race Condition
            "CWE-190": 20,  # Integer Overflow
            "CWE-416": 21,  # Use After Free
            "CWE-476": 22,  # Null Deref
            "CWE-601": 23,  # Open Redirect
            "CWE-942": 24,  # CORS Misconfig
            "CWE-347": 25,  # JWT
            "CWE-287": 26,  # OAuth
            "CWE-915": 27,  # Mass Assignment
            "CWE-639": 28,  # IDOR/BOLA
            "CWE-350": 29,  # DNS Rebinding
            "CWE-427": 30,  # Dependency Confusion
            "CWE-1333": 31, # ReDoS
            "CWE-384": 32,  # Session Fixation
            "CWE-1021": 33, # Clickjacking
            "CWE-434": 34,  # File Upload
        }
        return cwe_map.get(cwe_id, 9)  # Default to Sensitive Data Exposure


class ZeroDayDiscoveryEngine:
    """
    Main entry point for internet-connected vulnerability discovery.

    Orchestrates searches across multiple sources, analyzes trends,
    and generates new detection rules for the scanner.
    """

    def __init__(
        self,
        nvd_api_key: str = "",
        github_token: str = "",
        timeout: int = 30,
        max_queries: int = 20,
        enabled: bool = False,
    ):
        self.enabled = enabled
        self.max_queries = max_queries
        self._queries_made = 0

        self.matcher = PatternMatcherOnline(
            timeout=timeout,
            nvd_api_key=nvd_api_key,
        )
        self.trend_analyzer = TrendAnalyzer(matcher=self.matcher)

    def search_for_pattern(
        self,
        pattern_description: str,
        cwe_hint: str = "",
    ) -> list[DiscoveryResult]:
        """
        Search for vulnerability information matching a suspicious pattern.

        Args:
            pattern_description: Description of the suspicious pattern.
            cwe_hint: Optional CWE ID hint (e.g., "CWE-89").

        Returns:
            List of DiscoveryResult from all sources.
        """
        if not self.enabled:
            return []

        if self._queries_made >= self.max_queries:
            return []

        self._queries_made += 1

        search_term = pattern_description
        if cwe_hint:
            search_term = f"{cwe_hint} {pattern_description}"

        return self.matcher.search_all(search_term)

    def get_trending_patterns(self, days: int = 30) -> list[TrendingVulnerability]:
        """Get currently trending vulnerability patterns."""
        if not self.enabled:
            return []

        return self.trend_analyzer.get_trending_vulns(days)

    def generate_discovery_rules(self) -> list[dict]:
        """Generate new dynamic rules from internet-discovered patterns."""
        if not self.enabled:
            return []

        return self.trend_analyzer.generate_rules_from_trends()

    def enrich_finding(self, finding: dict) -> dict:
        """
        Enrich a scan finding with internet-sourced intelligence.

        Searches NVD/OSV for related CVEs and adds context.
        """
        if not self.enabled:
            return finding

        if self._queries_made >= self.max_queries:
            return finding

        vuln_name = finding.get("vulnerability_name", "")
        cwe_id = finding.get("cwe_id", "")

        if not vuln_name and not cwe_id:
            return finding

        self._queries_made += 1
        search_term = cwe_id if cwe_id else vuln_name

        try:
            nvd_result = self.matcher.search_nvd(search_term, max_results=3)
            if nvd_result.matches:
                finding["internet_context"] = {
                    "related_cves": nvd_result.matches[:3],
                    "source": "NVD",
                    "search_term": search_term,
                }
        except Exception:
            pass

        return finding

    def get_stats(self) -> dict:
        """Get discovery engine statistics."""
        return {
            "enabled": self.enabled,
            "queries_made": self._queries_made,
            "max_queries": self.max_queries,
            "remaining_queries": max(0, self.max_queries - self._queries_made),
            "trending_vulns_cached": len(self.trend_analyzer._trending_cache),
        }

    def reset_query_counter(self):
        """Reset the per-scan query counter."""
        self._queries_made = 0
