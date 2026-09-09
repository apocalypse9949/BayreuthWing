## 2024-05-15 - Extract invariant max() aggregation from HTML render loop
**Learning:** Found an O(N^2) bottleneck during HTML report rendering where `max()` over a static collection was being recalculated inside a loop.
**Action:** Always extract invariant aggregations, such as `max()` or `sum()` over static collections, outside of loops to prevent performance bottlenecks.
