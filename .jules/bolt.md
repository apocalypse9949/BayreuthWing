## 2024-06-23 - [O(N^2) Bottleneck in HTML Report Generation]
**Learning:** Found an O(N^2) performance bottleneck in the HTML reporter (`src/scanner/reporter.py`) where `max(vuln_counts.values())` was recalculated on every iteration of the findings loop.
**Action:** Always extract invariant aggregations (like `max()` or `sum()` over static collections) outside of loops to prevent unnecessary recalculations, especially in reporting/rendering components.
