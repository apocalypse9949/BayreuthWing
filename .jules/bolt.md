## 2025-05-18 - [HTML Report Rendering Invariants]
**Learning:** Discovered O(N^2) performance bottleneck caused by invariant aggregations like `max(vuln_counts.values())` repeatedly executed inside `for` loops in HTML chart rendering.
**Action:** Always extract invariant aggregations (`max()`, `sum()`) outside of rendering loops to ensure O(N) evaluation over static collections.
