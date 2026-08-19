## 2024-05-18 - Extracted invariant max() from HTML report generation loop
**Learning:** Calling `max()` on a static collection inside a loop causes an O(N^2) bottleneck, unnecessarily degrading performance especially during HTML report rendering where the vulnerability collection size can grow.
**Action:** Always extract invariant aggregations, such as `max()` or `sum()` over static collections, outside of loops to ensure O(N) linear time complexity.
