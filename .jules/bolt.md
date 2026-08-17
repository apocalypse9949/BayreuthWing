## 2024-08-17 - [Optimization: Avoid O(N^2) bottleneck in loops]
**Learning:** Found an O(N^2) bottleneck in `src/scanner/reporter.py` during HTML report rendering where `max(vuln_counts.values())` was being recalculated inside a loop iterating over the same dictionary.
**Action:** Always extract invariant aggregations (like `max()` or `sum()`) over static collections outside of loops to ensure O(N) complexity.
