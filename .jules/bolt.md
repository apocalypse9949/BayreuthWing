## 2024-06-18 - [HTML Report Rendering Bottleneck]
**Learning:** Invariant aggregations like `max()` calculated inside rendering loops over static collections cause O(N^2) bottlenecks, especially during HTML report generation.
**Action:** Always extract invariant calculations outside of loops.
