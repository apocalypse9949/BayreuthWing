## 2026-05-31 - O(N^2) Bottleneck in HTML Report Generation
**Learning:** The HTML report generation had an O(N^2) bottleneck because `max(vuln_counts.values())` was recalculated inside the loop for every vulnerability chart row.
**Action:** Extract invariant aggregations (`max()`, `sum()`) over static collections outside of loops to maintain O(N) complexity during rendering.