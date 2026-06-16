## 2026-06-16 - Prevent O(N^2) Bottleneck in HTML Report Rendering
**Learning:** Found an O(N^2) performance bottleneck in `src/scanner/reporter.py` where `max(vuln_counts.values())` was recalculated on every iteration of a loop during HTML report generation.
**Action:** Extract invariant aggregations, such as `max()` or `sum()` over static collections, outside of loops to ensure O(N) performance, especially in reporting components.
