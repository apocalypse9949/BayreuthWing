## 2024-07-10 - O(N^2) Bottleneck in HTML Report Generation
**Learning:** The HTML report generation looped over `vuln_counts.items()` and recalculated `max(vuln_counts.values())` on every iteration, causing an O(N^2) bottleneck for reports with many unique vulnerabilities.
**Action:** Extract invariant aggregations, such as `max()` or `sum()` over static collections, and calculate them outside of loops to prevent performance degradation.
