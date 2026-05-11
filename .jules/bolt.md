## 2024-05-11 - O(N^2) Bottleneck in HTML Report Generation
**Learning:** HTML report rendering contained an O(N^2) anti-pattern where invariant aggregations `max(vuln_counts.values())` were being calculated repeatedly inside the charting loop.
**Action:** Always extract invariant calculations like `max()` or `sum()` over static collections outside of loops, particularly in data-heavy reporting templates, to prevent severe performance degradation on large scans.
