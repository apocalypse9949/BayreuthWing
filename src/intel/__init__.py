"""
BAYREUTHWING — Threat Intelligence Module
Internet-connected security intelligence for real-time vulnerability data.
"""

from .cve_client import CVEClient
from .dependency_checker import DependencyChecker
from .github_scanner import GitHubScanner
from .threat_feed import ThreatIntelFeed

__all__ = ["CVEClient", "DependencyChecker", "GitHubScanner", "ThreatIntelFeed"]
