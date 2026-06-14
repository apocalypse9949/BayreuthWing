## 2024-06-14 - HTML Report O(N^2) Bottleneck
**Learning:** In `src/scanner/reporter.py`, `max(vuln_counts.values())` was being recalculated inside a loop for every vulnerability type, creating an O(N^2) bottleneck for large scan results during HTML report rendering.
**Action:** Always extract invariant aggregations over static collections outside of loops to maintain O(N) complexity.
