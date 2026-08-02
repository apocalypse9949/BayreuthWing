## 2026-08-02 - O(N^2) Bottlenecks in HTML Rendering
**Learning:** The HTML report generator (src/scanner/reporter.py) exhibited a codebase-specific anti-pattern where invariant aggregations (like `max(vuln_counts.values())`) were recalculated inside rendering loops, causing O(N^2) performance bottlenecks.
**Action:** Always extract invariant calculations like `max()` or `sum()` over static collections outside of iteration loops, especially in report generation or text rendering loops.
