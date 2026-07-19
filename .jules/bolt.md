## 2024-07-19 - Extract invariant aggregations from loops during HTML rendering
**Learning:** Redundant aggregations (like `max()`) inside loops in HTML report generation create significant O(N^2) bottlenecks when processing many vulnerabilities.
**Action:** Always extract invariant aggregations, such as `max()` or `sum()` over static collections, outside of loops to prevent performance degradation during report rendering.
