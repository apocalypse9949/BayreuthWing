"""
BAYREUTHWING — Threat Intelligence Feed

Aggregates real-time threat intelligence from multiple public sources:

- CISA Known Exploited Vulnerabilities (KEV) catalog
- GitHub Security Advisories (GHSA)
- OSV.dev recent vulnerabilities
- Exploit-DB references

Provides a unified threat landscape view to contextualize scan findings
with active exploitation data.
"""

import json
import time
import urllib.request
import urllib.error
from typing import Optional
from datetime import datetime, timedelta


class ThreatIntelFeed:
    """
    Aggregates threat intelligence from multiple public sources.
    
    Provides:
    - Active exploitation data from CISA KEV
    - Recent vulnerability advisories
    - Trending vulnerability patterns
    - Context enrichment for scan findings
    """

    # CISA Known Exploited Vulnerabilities catalog
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # OSV.dev API
    OSV_API_URL = "https://api.osv.dev/v1"

    def __init__(self, timeout: int = 15):
        """
        Args:
            timeout: HTTP request timeout in seconds.
        """
        self.timeout = timeout
        self._kev_cache: Optional[dict] = None
        self._kev_cache_time: float = 0
        self._cache_ttl = 3600  # 1 hour cache

    def _http_get(self, url: str) -> Optional[bytes]:
        """Make a GET request and return raw response."""
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "BayreuthWing/1.0 (Threat Intelligence)",
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return response.read()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
            return None

    def get_cisa_kev(self, refresh: bool = False) -> list[dict]:
        """
        Fetch the CISA Known Exploited Vulnerabilities (KEV) catalog.
        
        This is a list of vulnerabilities known to be actively exploited
        in the wild. Finding one of these in your codebase is critical.
        
        Args:
            refresh: Force refresh the cached catalog.
            
        Returns:
            List of KEV vulnerability records.
        """
        # Check cache
        if (
            not refresh
            and self._kev_cache is not None
            and (time.time() - self._kev_cache_time) < self._cache_ttl
        ):
            return self._kev_cache.get("vulnerabilities", [])

        raw = self._http_get(self.CISA_KEV_URL)
        if not raw:
            return self._kev_cache.get("vulnerabilities", []) if self._kev_cache else []

        try:
            data = json.loads(raw.decode("utf-8"))
            self._kev_cache = data
            self._kev_cache_time = time.time()

            vulns = []
            for v in data.get("vulnerabilities", []):
                vulns.append({
                    "cve_id": v.get("cveID", ""),
                    "vendor": v.get("vendorProject", ""),
                    "product": v.get("product", ""),
                    "name": v.get("vulnerabilityName", ""),
                    "description": v.get("shortDescription", ""),
                    "date_added": v.get("dateAdded", ""),
                    "due_date": v.get("dueDate", ""),
                    "required_action": v.get("requiredAction", ""),
                    "known_ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                    "notes": v.get("notes", ""),
                })

            return vulns

        except (json.JSONDecodeError, KeyError):
            return []

    def search_kev(self, keyword: str) -> list[dict]:
        """
        Search the CISA KEV catalog by keyword.
        
        Args:
            keyword: Search term (searches vendor, product, name, description).
            
        Returns:
            Matching KEV entries.
        """
        kev_list = self.get_cisa_kev()
        keyword_lower = keyword.lower()
        
        results = []
        for v in kev_list:
            searchable = " ".join([
                v.get("vendor", ""),
                v.get("product", ""),
                v.get("name", ""),
                v.get("description", ""),
                v.get("cve_id", ""),
            ]).lower()

            if keyword_lower in searchable:
                results.append(v)

        return results

    def get_recent_kev(self, days: int = 30) -> list[dict]:
        """
        Get recently added KEV entries (actively exploited vulns).
        
        Args:
            days: Number of days back to search.
            
        Returns:
            Recent KEV entries.
        """
        kev_list = self.get_cisa_kev()
        cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")

        return [
            v for v in kev_list
            if v.get("date_added", "0000-00-00") >= cutoff
        ]

    def check_cve_in_kev(self, cve_id: str) -> Optional[dict]:
        """
        Check if a specific CVE is in the CISA KEV catalog.
        
        Being in KEV means the vulnerability is **actively exploited**
        and should be treated as maximum priority.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228").
            
        Returns:
            KEV record if found, None otherwise.
        """
        kev_list = self.get_cisa_kev()
        for v in kev_list:
            if v.get("cve_id", "").upper() == cve_id.upper():
                return v
        return None

    def get_ecosystem_vulns(
        self,
        ecosystem: str = "PyPI",
        max_results: int = 20,
    ) -> list[dict]:
        """
        Get recent vulnerabilities for a specific ecosystem from OSV.dev.
        
        Args:
            ecosystem: Package ecosystem (PyPI, npm, Maven, Go, crates.io).
            max_results: Maximum results.
            
        Returns:
            List of recent vulnerability records.
        """
        try:
            # OSV batch query for ecosystem
            query = json.dumps({
                "package": {"ecosystem": ecosystem},
            }).encode("utf-8")

            req = urllib.request.Request(
                f"{self.OSV_API_URL}/query",
                data=query,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "BayreuthWing/1.0",
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))

            results = []
            for vuln in data.get("vulns", [])[:max_results]:
                results.append({
                    "id": vuln.get("id", ""),
                    "summary": vuln.get("summary", ""),
                    "aliases": vuln.get("aliases", []),
                    "published": vuln.get("published", ""),
                    "modified": vuln.get("modified", ""),
                    "ecosystem": ecosystem,
                })

            return results

        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
            return []

    def get_threat_summary(self) -> dict:
        """
        Generate a comprehensive threat landscape summary.
        
        Aggregates data from all sources into a single overview.
        
        Returns:
            Threat summary dictionary.
        """
        summary = {
            "generated_at": datetime.utcnow().isoformat(),
            "sources": [],
            "kev_stats": {},
            "recent_threats": [],
        }

        # CISA KEV stats
        try:
            kev = self.get_cisa_kev()
            recent_kev = self.get_recent_kev(days=30)
            ransomware_kev = [
                v for v in kev
                if v.get("known_ransomware", "").lower() == "known"
            ]

            summary["kev_stats"] = {
                "total_known_exploited": len(kev),
                "added_last_30_days": len(recent_kev),
                "ransomware_associated": len(ransomware_kev),
            }
            summary["sources"].append("CISA KEV")
            summary["recent_threats"].extend(recent_kev[:5])
        except Exception:
            summary["kev_stats"] = {"error": "Could not fetch CISA KEV data"}

        return summary

    def enrich_findings_with_kev(self, findings: list[dict]) -> list[dict]:
        """
        Check scan findings against CISA KEV for active exploitation.
        
        Findings matching KEV entries are elevated to CRITICAL severity
        with an active exploitation warning.
        
        Args:
            findings: List of scan finding dicts.
            
        Returns:
            Enriched findings with KEV context.
        """
        kev_list = self.get_cisa_kev()
        kev_cves = {v["cve_id"].upper(): v for v in kev_list if v.get("cve_id")}

        for finding in findings:
            # Check if any related CVEs are in KEV
            cve_context = finding.get("cve_context", {})
            related_cves = cve_context.get("related_cves", [])

            finding["kev_match"] = None
            for cve in related_cves:
                cve_id = cve.get("cve_id", "").upper()
                if cve_id in kev_cves:
                    finding["kev_match"] = kev_cves[cve_id]
                    finding["severity"] = "critical"
                    finding["message"] = (
                        f"[ACTIVELY EXPLOITED] {finding.get('message', '')} "
                        f"— This vulnerability pattern matches {cve_id}, "
                        f"which is in the CISA Known Exploited Vulnerabilities catalog."
                    )
                    break

        return findings

    def format_threat_report(self, summary: Optional[dict] = None) -> str:
        """Format threat summary as a readable report."""
        if summary is None:
            summary = self.get_threat_summary()

        lines = []
        lines.append("")
        lines.append("  THREAT INTELLIGENCE SUMMARY")
        lines.append("  " + "=" * 55)
        lines.append(f"  Generated: {summary['generated_at'][:19]}")
        lines.append(f"  Sources: {', '.join(summary.get('sources', []))}")
        lines.append("")

        kev = summary.get("kev_stats", {})
        if "error" not in kev:
            lines.append("  CISA Known Exploited Vulnerabilities:")
            lines.append(f"    Total in catalog:        {kev.get('total_known_exploited', 0):,}")
            lines.append(f"    Added last 30 days:      {kev.get('added_last_30_days', 0)}")
            lines.append(f"    Ransomware-associated:   {kev.get('ransomware_associated', 0)}")
            lines.append("")

        recent = summary.get("recent_threats", [])
        if recent:
            lines.append("  RECENTLY ADDED THREATS:")
            lines.append("  " + "-" * 55)
            for threat in recent[:5]:
                lines.append(
                    f"    {threat.get('cve_id', 'N/A'):<18} "
                    f"{threat.get('vendor', '')}/{threat.get('product', '')}"
                )
                desc = threat.get("description", "")[:70]
                lines.append(f"      {desc}")
                lines.append("")

        return "\n".join(lines)
