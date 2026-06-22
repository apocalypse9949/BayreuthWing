## 2024-06-22 - Extracting Invariants from Loops
**Learning:** Calculating aggregations like `max()` over static collections inside a loop creates an O(N^2) performance bottleneck, especially during HTML report rendering where the collection doesn't change during iteration.
**Action:** Always extract invariant aggregations outside of loops before iterating.
