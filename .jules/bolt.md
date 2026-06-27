## 2024-05-24 - HTML Report O(N^2) Aggregation Bottleneck
**Learning:** Found an O(N^2) performance bottleneck specific to the HTML report rendering engine where an invariant collection aggregation (`max(vuln_counts.values())`) was recalculating inside a loop for every vulnerability class, unnecessarily consuming CPU during large scans.
**Action:** Always extract invariant aggregations (like `max()` or `sum()`) over static collections outside of loops during report generation to avoid degrading performance on large vulnerability sets.
