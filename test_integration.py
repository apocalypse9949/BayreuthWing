"""Quick integration test of all Mythos-class engines."""

# Test 1: Adversarial Simulation
print("=" * 60)
print("TEST 1: Adversarial Simulation Engine")
print("=" * 60)

from src.scanner.adversarial_sim import AdversarialSimulator, ThreatActorLevel

sim = AdversarialSimulator()
findings = [
    {"vuln_class": 0, "severity": "critical", "confidence": 0.9, "vulnerability_name": "SQL Injection", "filepath": "app.py", "line": 42},
    {"vuln_class": 1, "severity": "high", "confidence": 0.8, "vulnerability_name": "XSS", "filepath": "views.py", "line": 15},
    {"vuln_class": 4, "severity": "critical", "confidence": 0.85, "vulnerability_name": "Broken Access Control", "filepath": "auth.py", "line": 88},
    {"vuln_class": 17, "severity": "critical", "confidence": 0.7, "vulnerability_name": "SSRF", "filepath": "api.py", "line": 120},
    {"vuln_class": 8, "severity": "critical", "confidence": 0.75, "vulnerability_name": "Insecure Deserialization", "filepath": "serializer.py", "line": 33},
]

results = sim.simulate(findings)
print("Simulations:", len(results["simulations"]))
print("Risk Matrix:", len(results["risk_matrix"]), "levels")
print("Priority Targets:", len(results["priority_targets"]))
print("Time:", results["simulation_time_ms"], "ms")
print(sim.get_simulation_summary())

# Test 2: Self-Evolution
print("=" * 60)
print("TEST 2: Self-Evolution Engine")
print("=" * 60)

from src.scanner.self_evolution import SelfEvolutionEngine
import tempfile, os

evo = SelfEvolutionEngine(
    state_dir=os.path.join(tempfile.mkdtemp(), "evo_test"),
    state_file="test_state.json",
)

scan_results = {
    "total_findings": 5,
    "severity_counts": {"critical": 3, "high": 1, "medium": 1},
    "files_scanned": 10,
    "findings": [
        {"vuln_class": 0, "severity": "critical", "matched_text": "cursor.execute('SELECT * FROM users WHERE id=' + user_id)", "source": "static_rule"},
        {"vuln_class": 0, "severity": "critical", "matched_text": "db.execute('SELECT name FROM items WHERE category=' + cat)", "source": "static_rule"},
        {"vuln_class": 0, "severity": "critical", "matched_text": "conn.execute('DELETE FROM logs WHERE date=' + date_str)", "source": "ml_model"},
        {"vuln_class": 1, "severity": "high", "matched_text": "element.innerHTML = userInput", "source": "static_rule"},
        {"vuln_class": 1, "severity": "high", "matched_text": "div.innerHTML = data.content", "source": "dynamic_rule"},
    ],
}

report = evo.evolve(scan_results)
print("New patterns:", len(report["new_patterns"]))
print("Promoted:", len(report["promoted_patterns"]))
print("Velocity:", report["improvement_velocity"])

# Run again to trigger confirmations
report2 = evo.evolve(scan_results)
print("\nAfter 2nd evolution:")
print("Confirmations:", report2.get("confirmations", 0))
print("Active patterns:", len(evo.get_active_patterns()))
print(evo.get_evolution_report())

# Test 3: Cognitive Engine
print("=" * 60)
print("TEST 3: Cognitive Reasoning Engine")
print("=" * 60)

from src.scanner.cognitive_engine import CognitiveEngine

cog = CognitiveEngine()
cognitive_results = cog.analyze(findings, scan_context={"target": "/test/app", "files_scanned": 5})
print("Correlations:", len(cognitive_results.get("correlations", [])))
print("Attack Paths:", len(cognitive_results.get("attack_paths", [])))
print("Blind Spots:", len(cognitive_results.get("blind_spots", [])))
print("Narratives:", len(cognitive_results.get("narratives", [])))

if cognitive_results.get("attack_paths"):
    print("\nSample Attack Path:")
    path = cognitive_results["attack_paths"][0]
    print(f"  Name: {path.get('name', 'N/A')}")
    print(f"  Steps: {len(path.get('steps', []))}")
    print(f"  Impact: {path.get('impact', 'N/A')}")

print("\n" + "=" * 60)
print("ALL INTEGRATION TESTS PASSED")
print("=" * 60)
