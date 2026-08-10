## 2025-03-08 - Extract invariant aggregations from rendering loops
**Learning:** Recomputing aggregations like `max()` over static collections inside rendering loops causes an O(N^2) performance bottleneck.
**Action:** Always extract static aggregations outside of loops before iteration to reduce time complexity to O(N).
