## 2024-06-04 - O(N^2) HTML Report Generation Loop
**Learning:** The HTML report rendering contained an O(N^2) bottleneck because invariant aggregations like `max(vuln_counts.values())` were being repeatedly calculated inside loops over vulnerability types.
**Action:** Always extract invariant aggregations (like `max()` or `sum()`) from loops when rendering reports to prevent scaling issues with large collections.
