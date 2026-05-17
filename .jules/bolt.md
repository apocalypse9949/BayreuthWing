## 2026-05-17 - O(N^2) bottleneck in HTML report chart rendering
**Learning:** Calculating invariant aggregations like `max(vuln_counts.values())` inside a loop processing chart rows caused an O(N^2) bottleneck during HTML report generation.
**Action:** Always extract invariant aggregations over static collections outside of loops to prevent unnecessary performance degradation.
