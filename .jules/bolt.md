## 2024-05-24 - Optimization: Extract max() from generation loop
**Learning:** Invariant aggregations like `max()` over static collections inside loops cause O(N^2) bottlenecks, especially during HTML report rendering with many categories.
**Action:** Always extract invariant aggregations out of loops to turn O(N^2) operations into O(N).
