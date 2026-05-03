## 2024-05-03 - O(N^2) Bottleneck in HTML Report Generation
**Learning:** Discovered an O(N^2) performance bottleneck specific to this codebase's architecture where invariant aggregations like `max(vuln_counts.values())` were computed inside loops rendering HTML reports, severely degrading performance for large vulnerability sets.
**Action:** Always extract invariant calculations like `max()` or `sum()` over static collections to be calculated outside of rendering loops to ensure O(N) performance.
