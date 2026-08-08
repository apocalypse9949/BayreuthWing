## 2024-05-18 - Avoid O(N^2) bottlenecks in HTML reporting
**Learning:** Found O(N^2) bottleneck during HTML report rendering because `max(vuln_counts.values())` was being calculated inside the rendering loop. Invariant aggregations over static collections must be extracted.
**Action:** Always extract invariant aggregations (like `max()` or `sum()`) outside of loops, particularly when generating reports over potentially large vulnerability data sets.
