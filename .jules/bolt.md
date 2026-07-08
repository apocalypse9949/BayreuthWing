## 2024-07-08 - Extract invariant aggregations outside of loops
**Learning:** The `max()` aggregation over `vuln_counts.values()` was being calculated inside the loop rendering HTML chart bars, causing an O(N^2) bottleneck for large result sets.
**Action:** Always extract invariant aggregations, such as `max()` or `sum()` over static collections, and calculate them outside of loops.
