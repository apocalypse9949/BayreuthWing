from .binary_inspector import BinaryInspector
from .api_inferencer import ApiInferencer
from .endpoint_discoverer import EndpointDiscoverer
from .hidden_route_detector import HiddenRouteDetector
from .decompiled_logic_analyzer import DecompiledLogicAnalyzer

class ReverseEngineeringAnalyzer:
    """Orchestrates all reverse engineering analysis modules."""

    def __init__(self):
        self.binary_inspector = BinaryInspector()
        self.api_inferencer = ApiInferencer()
        self.endpoint_discoverer = EndpointDiscoverer()
        self.hidden_route_detector = HiddenRouteDetector()
        self.decompiled_logic_analyzer = DecompiledLogicAnalyzer()

    def analyze(self, code: str, filepath: str, language: str) -> list[dict]:
        """Run all reverse engineering checks."""
        findings = []

        # Binary inspection (usually on file content directly)
        findings.extend(self.binary_inspector.inspect(filepath))

        # Text/Code based analysis
        if code:
            findings.extend(self.api_inferencer.infer(code, language))
            findings.extend(self.endpoint_discoverer.discover(code, language))
            findings.extend(self.hidden_route_detector.detect(code, language))
            findings.extend(self.decompiled_logic_analyzer.analyze(code, language))

        return findings
