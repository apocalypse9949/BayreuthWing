## 2024-07-27 - Loop invariant optimization in HTML generator
**Learning:** Found an O(N^2) bottleneck in `src/scanner/reporter.py` where `max(vuln_counts.values())` was being calculated repeatedly inside a loop over `vuln_counts.items()`.
**Action:** Always extract invariant aggregations (like `max()`, `sum()`) over static collections outside of loops to prevent unnecessary redundant calculations.
