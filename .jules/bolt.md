## 2024-05-24 - [Extract invariants from HTML rendering loops]
**Learning:** Found redundant invariant aggregation (`max()`) inside a loop during HTML report generation in `src/scanner/reporter.py`, leading to O(N^2) performance bottlenecks.
**Action:** Always extract invariant aggregations over static collections outside of loops, particularly in rendering code paths.
