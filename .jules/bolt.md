## 2024-05-24 - Extracted Invariant Aggregation in Loop
**Learning:** Found an O(N^2) performance bottleneck during HTML report rendering due to the recalculation of invariant aggregation `max(vuln_counts.values())` inside the vulnerability counts loop.
**Action:** Always extract static aggregations like `max()` or `sum()` over static collections to be calculated outside of loops to improve efficiency.
