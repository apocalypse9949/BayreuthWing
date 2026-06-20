## 2024-06-20 - Invariant Aggregations in Rendering Loops
**Learning:** Calculating aggregations like `max()` or `sum()` over static collections inside rendering loops (like `vuln_counts` in HTML report generation) causes O(N^2) performance bottlenecks. This becomes increasingly noticeable as the number of vulnerabilities or categories grows.
**Action:** Always extract and calculate invariant aggregations outside of loops to ensure O(N) linear time complexity.
