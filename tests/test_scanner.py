"""
BAYREUTHWING — Test Suite: Scanner Tests
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.scanner.engine import ScanEngine, Finding
from src.scanner.rules import RuleEngine
from src.scanner.analyzer import CodeAnalyzer
from src.scanner.reporter import ReportGenerator
from src.data.preprocessor import CodePreprocessor


class TestRuleEngine:
    """Tests for the static rule engine."""

    def setup_method(self):
        self.engine = RuleEngine()

    def test_total_rules(self):
        assert self.engine.total_rules >= 90  # We have 90+ rules

    def test_detects_sql_injection(self):
        code = '''query = "SELECT * FROM users WHERE name = '" + username + "'"
cursor.execute(query)'''
        findings = self.engine.scan(code, "python")
        vuln_classes = [f["vuln_class"] for f in findings]
        assert 0 in vuln_classes  # SQL Injection

    def test_detects_command_injection(self):
        code = 'os.system("ping " + host)'
        findings = self.engine.scan(code, "python")
        vuln_classes = [f["vuln_class"] for f in findings]
        assert 2 in vuln_classes  # Command Injection

    def test_detects_hardcoded_password(self):
        code = 'password = "SuperSecret123!"'
        findings = self.engine.scan(code, "python")
        vuln_classes = [f["vuln_class"] for f in findings]
        assert 4 in vuln_classes  # Hardcoded Credentials

    def test_detects_weak_crypto(self):
        code = 'hashlib.md5(data)'
        findings = self.engine.scan(code, "python")
        vuln_classes = [f["vuln_class"] for f in findings]
        assert 6 in vuln_classes  # Weak Crypto

    def test_detects_pickle(self):
        code = 'data = pickle.loads(raw_bytes)'
        findings = self.engine.scan(code, "python")
        vuln_classes = [f["vuln_class"] for f in findings]
        assert 5 in vuln_classes  # Insecure Deserialization

    def test_detects_buffer_overflow(self):
        code = 'strcpy(buffer, input);'
        findings = self.engine.scan(code, "c")
        vuln_classes = [f["vuln_class"] for f in findings]
        assert 7 in vuln_classes  # Buffer Overflow

    def test_safe_code_minimal_findings(self):
        code = '''def add(a, b):
    return a + b

result = add(1, 2)
print(result)'''
        findings = self.engine.scan(code, "python")
        # Safe code should have very few or no findings
        assert len(findings) <= 2

    def test_language_filtering(self):
        code = 'strcpy(buffer, input);'
        # C rule shouldn't match in Python context
        findings = self.engine.scan(code, "python")
        c_findings = [f for f in findings if f["rule_id"].startswith("BOF")]
        # BOF rules are limited to C/C++
        assert len(c_findings) == 0


class TestCodeAnalyzer:
    """Tests for the code flow analyzer."""

    def setup_method(self):
        self.analyzer = CodeAnalyzer()

    def test_detects_dangerous_calls(self):
        code = '''import os
os.system("rm -rf /")
eval(user_input)'''
        results = self.analyzer.analyze(code, "test.py")
        calls = results["dangerous_calls"]
        func_names = [c["function"] for c in calls]
        assert "os.system" in func_names
        assert "eval" in func_names

    def test_detects_python_language(self):
        code = '''def hello():
    print("world")'''
        results = self.analyzer.analyze(code, "test.py")
        assert results["language"] == "python"

    def test_detects_framework(self):
        code = '''from flask import Flask
app = Flask(__name__)
@app.route("/")
def index():
    return "hello"'''
        results = self.analyzer.analyze(code, "app.py")
        assert "flask" in results["frameworks"]


class TestCodePreprocessor:
    """Tests for the code preprocessor."""

    def setup_method(self):
        self.preprocessor = CodePreprocessor()

    def test_language_detection_by_extension(self):
        assert self.preprocessor.detect_language("", "test.py") == "python"
        assert self.preprocessor.detect_language("", "app.js") == "javascript"
        assert self.preprocessor.detect_language("", "Main.java") == "java"
        assert self.preprocessor.detect_language("", "main.go") == "go"
        assert self.preprocessor.detect_language("", "lib.rs") == "rust"

    def test_language_detection_by_content(self):
        python_code = "def hello():\n    print('world')"
        assert self.preprocessor.detect_language(python_code) == "python"

    def test_normalize(self):
        code = "line1  \r\nline2  \r\n\r\n\r\n\r\nline3"
        result = self.preprocessor.normalize(code)
        assert "\r" not in result
        assert result.endswith("\n")

    def test_chunk_code(self):
        code = "x = 1\n" * 500
        chunks = self.preprocessor.chunk_code(code)
        assert len(chunks) >= 1
        assert all("code" in c for c in chunks)

    def test_framework_detection(self):
        django_code = "from django.http import HttpResponse"
        frameworks = self.preprocessor.detect_frameworks(django_code)
        assert "django" in frameworks


class TestScanEngine:
    """Tests for the hybrid scan engine."""

    def setup_method(self):
        self.engine = ScanEngine(config={
            "scanner": {"confidence_threshold": 0.3}
        })

    def test_scan_vulnerable_python(self):
        test_file = os.path.join(
            os.path.dirname(__file__), "sample_targets", "vuln_python.py"
        )
        if os.path.exists(test_file):
            findings = self.engine.scan_file(test_file)
            assert len(findings) > 0
            severities = set(f.severity for f in findings)
            assert "critical" in severities or "high" in severities

    def test_scan_vulnerable_javascript(self):
        test_file = os.path.join(
            os.path.dirname(__file__), "sample_targets", "vuln_javascript.js"
        )
        if os.path.exists(test_file):
            findings = self.engine.scan_file(test_file)
            assert len(findings) > 0

    def test_scan_directory(self):
        test_dir = os.path.join(
            os.path.dirname(__file__), "sample_targets"
        )
        if os.path.exists(test_dir):
            results = self.engine.scan_directory(test_dir)
            assert results["files_scanned"] > 0
            assert results["total_findings"] > 0

    def test_finding_has_cwe(self):
        test_file = os.path.join(
            os.path.dirname(__file__), "sample_targets", "vuln_python.py"
        )
        if os.path.exists(test_file):
            findings = self.engine.scan_file(test_file)
            if findings:
                assert findings[0].cwe_id.startswith("CWE-")


class TestReportGenerator:
    """Tests for report generation."""

    def setup_method(self):
        self.reporter = ReportGenerator()
        self.sample_results = {
            "target": "/test/path",
            "scan_time": 1.5,
            "files_scanned": 3,
            "total_findings": 5,
            "severity_counts": {"critical": 2, "high": 1, "medium": 1, "low": 1},
            "vulnerability_counts": {"SQL Injection": 2, "XSS": 1, "Command Injection": 2},
            "findings": [
                {
                    "vuln_class": 0,
                    "vulnerability_name": "SQL Injection",
                    "cwe_id": "CWE-89",
                    "owasp": "A03:2021",
                    "filepath": "/test/app.py",
                    "line": 10,
                    "message": "SQL injection detected",
                    "severity": "critical",
                    "confidence": 0.95,
                    "source": "static_rule",
                    "rule_id": "SQL001",
                    "matched_text": "query = \"SELECT * FROM users WHERE name = '\" + name",
                    "remediation": ["Use parameterized queries"],
                },
            ],
            "engine_info": {
                "ml_enabled": False,
                "rules_enabled": True,
                "flow_enabled": True,
                "total_rules": 100,
            },
        }

    def test_console_report(self):
        report = self.reporter.generate(self.sample_results, format="console")
        assert "BAYREUTHWING" in report
        assert "SQL Injection" in report

    def test_json_report(self):
        import json
        report = self.reporter.generate(self.sample_results, format="json")
        data = json.loads(report)
        assert "findings" in data
        assert data["scan_summary"]["total_findings"] == 5

    def test_html_report(self):
        report = self.reporter.generate(self.sample_results, format="html")
        assert "<!DOCTYPE html>" in report
        assert "BAYREUTHWING" in report
        assert "SQL Injection" in report


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
