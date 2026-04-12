"""
BAYREUTHWING — GitHub Repository Scanner

Clones and scans public GitHub repositories by URL. Enables remote
security auditing of open-source projects without manually downloading code.

Features:
- Clone public repos via HTTPS
- Auto-detect project type and run appropriate scans
- Scan specific branches or commits
- Clean up cloned repos after scanning
- Rate-limiting aware for GitHub API
"""

import os
import json
import shutil
import tempfile
import subprocess
import urllib.request
import urllib.error
from typing import Optional
from pathlib import Path


class GitHubScanner:
    """
    Scans GitHub repositories for security vulnerabilities.
    
    Can operate in two modes:
    1. Clone mode — clones the repo and runs full local scanning
    2. API mode — uses GitHub API for metadata and advisory checks
    """

    GITHUB_API_BASE = "https://api.github.com"

    def __init__(
        self,
        github_token: Optional[str] = None,
        work_dir: Optional[str] = None,
        timeout: int = 15,
    ):
        """
        Args:
            github_token: Optional GitHub personal access token for higher API limits.
            work_dir: Working directory for cloned repos. Uses temp dir if not specified.
            timeout: HTTP request timeout.
        """
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")
        self.work_dir = work_dir
        self.timeout = timeout

    def _github_api_request(self, endpoint: str) -> Optional[dict]:
        """Make a request to the GitHub REST API."""
        url = f"{self.GITHUB_API_BASE}/{endpoint.lstrip('/')}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "BayreuthWing/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            print(f"  [GitHub] API error: {e}")
            return None

    def get_repo_info(self, owner: str, repo: str) -> Optional[dict]:
        """
        Fetch repository metadata from GitHub API.
        
        Args:
            owner: Repository owner (e.g., "django").
            repo: Repository name (e.g., "django").
            
        Returns:
            Repository info dict or None.
        """
        data = self._github_api_request(f"/repos/{owner}/{repo}")
        if not data:
            return None

        return {
            "full_name": data.get("full_name", ""),
            "description": data.get("description", ""),
            "language": data.get("language", ""),
            "default_branch": data.get("default_branch", "main"),
            "stars": data.get("stargazers_count", 0),
            "forks": data.get("forks_count", 0),
            "open_issues": data.get("open_issues_count", 0),
            "created_at": data.get("created_at", ""),
            "updated_at": data.get("updated_at", ""),
            "license": data.get("license", {}).get("spdx_id", "Unknown"),
            "topics": data.get("topics", []),
            "visibility": data.get("visibility", "public"),
            "archived": data.get("archived", False),
            "clone_url": data.get("clone_url", ""),
            "html_url": data.get("html_url", ""),
        }

    def get_security_advisories(self, owner: str, repo: str) -> list[dict]:
        """
        Fetch security advisories for a repository.
        
        Args:
            owner: Repository owner.
            repo: Repository name.
            
        Returns:
            List of advisory records.
        """
        data = self._github_api_request(
            f"/repos/{owner}/{repo}/security-advisories"
        )

        if not data or not isinstance(data, list):
            # Advisories endpoint may return 404 for repos without advisories
            return []

        advisories = []
        for advisory in data:
            advisories.append({
                "ghsa_id": advisory.get("ghsa_id", ""),
                "cve_id": advisory.get("cve_id", ""),
                "summary": advisory.get("summary", ""),
                "severity": advisory.get("severity", ""),
                "state": advisory.get("state", ""),
                "published_at": advisory.get("published_at", ""),
                "vulnerabilities": [
                    {
                        "package": v.get("package", {}).get("name", ""),
                        "ecosystem": v.get("package", {}).get("ecosystem", ""),
                        "vulnerable_range": v.get("vulnerable_version_range", ""),
                        "patched_version": v.get("patched_versions", ""),
                    }
                    for v in advisory.get("vulnerabilities", [])
                ],
            })

        return advisories

    def clone_and_scan(
        self,
        repo_url: str,
        branch: Optional[str] = None,
        scan_engine=None,
        cleanup: bool = True,
    ) -> dict:
        """
        Clone a GitHub repository and run a full security scan.
        
        Args:
            repo_url: GitHub repository URL (HTTPS).
            branch: Specific branch to clone. Defaults to main/master.
            scan_engine: ScanEngine instance to use. Creates one if not provided.
            cleanup: Whether to delete cloned repo after scanning.
            
        Returns:
            Scan results dictionary with repo metadata.
        """
        # Parse owner/repo from URL
        owner, repo = self._parse_repo_url(repo_url)
        if not owner or not repo:
            return {"error": f"Invalid GitHub URL: {repo_url}"}

        # Fetch repo metadata
        repo_info = self.get_repo_info(owner, repo)

        # Create clone directory
        if self.work_dir:
            clone_dir = os.path.join(self.work_dir, f"{owner}_{repo}")
        else:
            clone_dir = os.path.join(tempfile.gettempdir(), f"bw_{owner}_{repo}")

        # Clean existing clone
        if os.path.exists(clone_dir):
            shutil.rmtree(clone_dir, ignore_errors=True)

        try:
            # Clone the repository
            print(f"  Cloning {owner}/{repo}...")
            clone_url = f"https://github.com/{owner}/{repo}.git"
            cmd = ["git", "clone", "--depth", "1"]
            if branch:
                cmd.extend(["--branch", branch])
            cmd.extend([clone_url, clone_dir])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                return {
                    "error": f"Clone failed: {result.stderr.strip()}",
                    "repo_info": repo_info,
                }

            print(f"  Cloned to: {clone_dir}")

            # Create or use scan engine
            if scan_engine is None:
                from ..scanner.engine import ScanEngine
                scan_engine = ScanEngine()

            # Run the scan
            print(f"  Scanning {owner}/{repo}...")
            scan_results = scan_engine.scan_directory(clone_dir, recursive=True)

            # Fetch advisories
            advisories = self.get_security_advisories(owner, repo)

            # Check dependencies
            from .dependency_checker import DependencyChecker
            dep_checker = DependencyChecker()
            dep_results = dep_checker.scan_project(clone_dir)

            # Combine results
            combined = {
                "repo_url": repo_url,
                "repo_info": repo_info,
                "code_scan": scan_results,
                "dependency_scan": {
                    "total_dependencies": dep_results["total_dependencies"],
                    "vulnerable_dependencies": dep_results["vulnerable_dependencies"],
                    "vulnerabilities": dep_results["vulnerabilities"][:20],
                },
                "github_advisories": advisories,
                "scan_summary": {
                    "code_findings": scan_results.get("total_findings", 0),
                    "dep_vulnerabilities": dep_results["vulnerable_dependencies"],
                    "advisories": len(advisories),
                    "files_scanned": scan_results.get("files_scanned", 0),
                },
            }

            return combined

        except subprocess.TimeoutExpired:
            return {"error": "Clone timed out (120s limit)"}
        except FileNotFoundError:
            return {"error": "git is not installed or not in PATH"}
        except Exception as e:
            return {"error": f"Scan failed: {str(e)}"}
        finally:
            if cleanup and os.path.exists(clone_dir):
                shutil.rmtree(clone_dir, ignore_errors=True)

    def search_repos(
        self,
        query: str,
        language: Optional[str] = None,
        sort: str = "stars",
        max_results: int = 10,
    ) -> list[dict]:
        """
        Search GitHub repositories.
        
        Args:
            query: Search query string.
            language: Filter by programming language.
            sort: Sort by 'stars', 'forks', 'updated'.
            max_results: Maximum results.
            
        Returns:
            List of repository info dicts.
        """
        search_query = query
        if language:
            search_query += f" language:{language}"

        params = urllib.parse.urlencode({
            "q": search_query,
            "sort": sort,
            "per_page": min(max_results, 30),
        })

        data = self._github_api_request(f"/search/repositories?{params}")
        if not data:
            return []

        results = []
        for item in data.get("items", [])[:max_results]:
            results.append({
                "full_name": item.get("full_name", ""),
                "description": item.get("description", "")[:200],
                "language": item.get("language", ""),
                "stars": item.get("stargazers_count", 0),
                "url": item.get("html_url", ""),
            })

        return results

    def _parse_repo_url(self, url: str) -> tuple[Optional[str], Optional[str]]:
        """
        Parse owner and repo name from a GitHub URL.
        
        Handles:
        - https://github.com/owner/repo
        - https://github.com/owner/repo.git
        - github.com/owner/repo
        - owner/repo
        """
        url = url.strip().rstrip("/")

        # Remove .git suffix
        if url.endswith(".git"):
            url = url[:-4]

        # Handle full URLs
        if "github.com" in url:
            parts = url.split("github.com/")
            if len(parts) == 2:
                path_parts = parts[1].split("/")
                if len(path_parts) >= 2:
                    return path_parts[0], path_parts[1]

        # Handle owner/repo format
        if "/" in url and "://" not in url:
            parts = url.split("/")
            if len(parts) == 2:
                return parts[0], parts[1]

        return None, None
