## 2024-06-12 - Invariant aggregations in HTML reporter loops
**Learning:** The HTML report rendering engine (`src/scanner/reporter.py`) had a codebase-specific anti-pattern where invariant aggregations (`max()`) were calculated inside the vulnerability visualization loop, causing unnecessary O(N^2) complexity during report generation.
**Action:** Always extract invariant calculations (like max or sum over static collections) outside of loops when building template strings or visualizations.
