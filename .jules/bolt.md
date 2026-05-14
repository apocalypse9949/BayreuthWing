## 2024-05-14 - HTML Report O(N^2) Bottleneck
**Learning:** Found an O(N^2) performance bottleneck during HTML report rendering where `max(vuln_counts.values())` was re-evaluated on every iteration of a loop.
**Action:** Always extract invariant aggregations (like `max()` or `sum()`) over static collections outside of loops to prevent unnecessary recalculations.
