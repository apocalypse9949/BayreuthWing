## 2024-05-24 - [Avoid O(N^2) in HTML Report Rendering]
**Learning:** Identified a codebase-specific anti-pattern where invariant aggregations like `max(vuln_counts.values())` were recalculated inside the loop in `src/scanner/reporter.py`, leading to O(N^2) rendering performance.
**Action:** Always extract invariant aggregations over static collections outside of loops.
