"""
BAYREUTHWING — CVE/NVD API Client

Queries the NIST National Vulnerability Database (NVD) API for real-time
CVE data. Supports searching by keyword, CPE, CWE, and severity.

NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0
No API key required for basic use (rate-limited to ~5 requests/30s).
With API key: 50 requests/30s.

This module enables BAYREUTHWING to correlate detected vulnerability
patterns with known CVEs, providing real-world context and severity data.
"""

import json
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import Optional
from datetime import datetime, timedelta


class CVEClient:
    """
    Client for the NIST National Vulnerability Database (NVD) API v2.0.
    
    Provides real-time CVE lookup to enrich scan findings with:
    - Known CVE identifiers matching detected patterns
    - CVSS severity scores from the national database
    - Affected software versions and vendor information
    - Published exploit references
    """

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Rate limiting: 5 requests per 30 seconds without key
    RATE_LIMIT_DELAY = 6.0  # seconds between requests (no API key)
    RATE_LIMIT_DELAY_KEYED = 0.6  # seconds with API key

    def __init__(self, api_key: Optional[str] = None, timeout: int = 15):
        """
        Args:
            api_key: Optional NVD API key for higher rate limits.
                     Get one at https://nvd.nist.gov/developers/request-an-api-key
            timeout: HTTP request timeout in seconds.
        """
        self.api_key = api_key
        self.timeout = timeout
        self._last_request_time = 0.0
        self._cache: dict[str, dict] = {}

    def _rate_limit(self):
        """Enforce rate limiting between API calls."""
        delay = self.RATE_LIMIT_DELAY_KEYED if self.api_key else self.RATE_LIMIT_DELAY
        elapsed = time.time() - self._last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_request_time = time.time()

    def _make_request(self, params: dict) -> Optional[dict]:
        """
        Make a GET request to the NVD API.
        
        Args:
            params: Query parameters.
            
        Returns:
            JSON response as dict, or None on failure.
        """
        self._rate_limit()

        query_string = urllib.parse.urlencode(params)
        url = f"{self.NVD_API_BASE}?{query_string}"

        headers = {
            "User-Agent": "BayreuthWing/1.0 (Security Scanner)",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
                return data
        except urllib.error.HTTPError as e:
            if e.code == 403:
                print(f"  [NVD] Rate limited. Waiting before retry...")
                time.sleep(30)
                return None
            elif e.code == 404:
                return None
            else:
                print(f"  [NVD] HTTP Error {e.code}: {e.reason}")
                return None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            print(f"  [NVD] Connection error: {e}")
            return None

    def search_by_keyword(
        self,
        keyword: str,
        max_results: int = 10,
        severity: Optional[str] = None,
    ) -> list[dict]:
        """
        Search CVEs by keyword.
        
        Args:
            keyword: Search term (e.g., "sql injection python").
            max_results: Maximum number of results.
            severity: Filter by CVSS v3 severity: LOW, MEDIUM, HIGH, CRITICAL.
            
        Returns:
            List of simplified CVE records.
        """
        cache_key = f"kw:{keyword}:{severity}:{max_results}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(max_results, 50),
        }
        if severity:
            params["cvssV3Severity"] = severity.upper()

        data = self._make_request(params)
        if not data:
            return []

        results = self._parse_cve_response(data)
        self._cache[cache_key] = results
        return results

    def search_by_cwe(self, cwe_id: str, max_results: int = 10) -> list[dict]:
        """
        Search CVEs by CWE identifier.
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-89" for SQL injection).
            max_results: Maximum results.
            
        Returns:
            List of CVE records matching the CWE.
        """
        # NVD API uses cweId parameter
        cwe_num = cwe_id.replace("CWE-", "")
        cache_key = f"cwe:{cwe_id}:{max_results}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        params = {
            "cweId": f"CWE-{cwe_num}",
            "resultsPerPage": min(max_results, 50),
        }

        data = self._make_request(params)
        if not data:
            return []

        results = self._parse_cve_response(data)
        self._cache[cache_key] = results
        return results

    def get_cve(self, cve_id: str) -> Optional[dict]:
        """
        Fetch a specific CVE by ID.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228").
            
        Returns:
            CVE record dict, or None if not found.
        """
        cache_key = f"id:{cve_id}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        params = {"cveId": cve_id}
        data = self._make_request(params)
        if not data:
            return None

        results = self._parse_cve_response(data)
        if results:
            self._cache[cache_key] = results[0]
            return results[0]
        return None

    def search_recent(
        self,
        days: int = 7,
        severity: Optional[str] = None,
        max_results: int = 20,
    ) -> list[dict]:
        """
        Search for recently published CVEs.
        
        Args:
            days: Number of days back to search.
            severity: Optional severity filter.
            max_results: Maximum results.
            
        Returns:
            List of recent CVE records.
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": min(max_results, 50),
        }
        if severity:
            params["cvssV3Severity"] = severity.upper()

        data = self._make_request(params)
        if not data:
            return []

        return self._parse_cve_response(data)

    def _parse_cve_response(self, data: dict) -> list[dict]:
        """Parse NVD API response into simplified CVE records."""
        results = []
        vulnerabilities = data.get("vulnerabilities", [])

        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "Unknown")

            # Extract description
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Extract CVSS v3.1 score
            metrics = cve.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])
            cvss_score = None
            cvss_severity = None
            cvss_vector = None
            if cvss_v31:
                cvss_data = cvss_v31[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity")
                cvss_vector = cvss_data.get("vectorString")

            # Extract CWE IDs
            weaknesses = cve.get("weaknesses", [])
            cwe_ids = []
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    value = desc.get("value", "")
                    if value.startswith("CWE-"):
                        cwe_ids.append(value)

            # Extract references
            references = []
            for ref in cve.get("references", [])[:5]:  # Limit to 5
                references.append({
                    "url": ref.get("url", ""),
                    "source": ref.get("source", ""),
                    "tags": ref.get("tags", []),
                })

            # Published date
            published = cve.get("published", "")

            results.append({
                "cve_id": cve_id,
                "description": description[:500],  # Truncate long descriptions
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "cvss_vector": cvss_vector,
                "cwe_ids": cwe_ids,
                "references": references,
                "published": published[:10],  # Just the date
            })

        return results

    def enrich_finding(self, finding: dict) -> dict:
        """
        Enrich a scan finding with real-world CVE data.
        
        Searches the NVD for CVEs matching the finding's CWE ID
        and vulnerability type, adding relevant CVE context.
        
        Args:
            finding: A scan finding dictionary.
            
        Returns:
            Finding dict with added 'cve_context' field.
        """
        cwe_id = finding.get("cwe_id", "")
        vuln_name = finding.get("vulnerability_name", "")

        # Search by CWE
        cves = []
        if cwe_id and cwe_id.startswith("CWE-"):
            cves = self.search_by_cwe(cwe_id, max_results=3)

        finding["cve_context"] = {
            "related_cves": cves[:3],
            "total_known_cves": len(cves),
            "data_source": "NIST NVD",
            "lookup_time": datetime.utcnow().isoformat(),
        }

        return finding
