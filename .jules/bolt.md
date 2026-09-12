## 2024-09-12 - Extract Loop Invariants in Reporter
**Learning:** In the HTML report generation loop, calculating `max(vuln_counts.values())` inside the loop causes an O(N^2) bottleneck.
**Action:** Extract invariant aggregations, such as `max()` or `sum()` over static collections, outside of loops to improve performance.
