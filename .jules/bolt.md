## 2025-02-27 - Extracting Invariants from Loops
**Learning:** Found an O(N^2) performance bottleneck during HTML report rendering due to an invariant aggregation (`max()`) computed inside a loop over static collections.
**Action:** Always extract invariant aggregations (like `max()` or `sum()`) over static collections outside of loops to prevent O(N^2) complexity.
