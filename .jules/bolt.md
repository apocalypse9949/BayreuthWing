## 2024-05-24 - Extract invariant aggregations from loops
**Learning:** Found an O(N^2) performance bottleneck in HTML report rendering due to recalculating `max()` over static collections inside a loop.
**Action:** Always extract and calculate invariant aggregations outside of loops to ensure O(N) performance.
