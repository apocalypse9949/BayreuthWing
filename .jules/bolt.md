## 2024-05-24 - HTML Report O(N^2) Aggregation
**Learning:** Found O(N^2) bottleneck during HTML report rendering due to max() aggregation inside a loop.
**Action:** Always extract invariant aggregations (like max or sum) from loops to avoid redundant O(N) calculations per iteration.
