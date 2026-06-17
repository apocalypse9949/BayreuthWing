## 2026-06-17 - O(N) instead of O(N^2) invariant extraction in HTML rendering
**Learning:** Found that `max(vuln_counts.values())` was being recalculated inside the `for` loop in HTML report generation, causing an unnecessary O(N^2) complexity over vulnerability counts.
**Action:** Always extract invariant aggregations (like `max()` or `sum()`) over static collections outside of loops to prevent N^2 bottlenecks.
