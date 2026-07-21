## 2024-05-01 - O(N^2) Bottleneck in HTML Report Generation
**Learning:** Found an invariant aggregation `max(vuln_counts.values())` inside a loop in `reporter.py`, causing unnecessary O(N^2) complexity when building vulnerability charts.
**Action:** Always extract invariant computations (like `max()`, `sum()`) out of loops, especially over static collections, to improve rendering performance.
