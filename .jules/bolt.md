## 2024-05-24 - Extracted Invariant Aggregations
**Learning:** Calculating aggregations like `max()` over static collections inside a loop causes an O(N^2) performance bottleneck during HTML report rendering.
**Action:** Always extract invariant aggregations outside of loops to ensure O(N) complexity.
