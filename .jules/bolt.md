## 2026-08-13 - O(N^2) Bottleneck in HTML Report Generation
**Learning:** Recalculating invariant aggregations like `max()` over static collections inside a loop causes an O(N^2) performance bottleneck.
**Action:** Always extract and calculate invariant aggregations outside of loops to improve performance.
