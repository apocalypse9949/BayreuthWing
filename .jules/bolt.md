## 2025-02-18 - HTML Report Generation Bottleneck
**Learning:** Found an O(N^2) performance bottleneck in the HTML report generator where an invariant aggregation max() was recalculated on every iteration of a loop.
**Action:** Always extract invariant aggregations over static collections outside of loops to prevent unnecessary recalculations.
