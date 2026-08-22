## 2024-05-23 - Avoid Recalculating Loop Invariants
**Learning:** Invariant aggregations like `max()` over static collections inside loops can cause O(N^2) performance bottlenecks during report generation.
**Action:** Always extract and calculate static aggregations outside of loop bodies.
