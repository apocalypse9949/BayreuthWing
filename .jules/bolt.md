## 2026-05-26 - O(N^2) Loop Bottleneck in HTML Report Generation
**Learning:** Recalculating invariant aggregations like `max()` over static collections inside a loop causes an O(N^2) performance bottleneck, especially during HTML report rendering.
**Action:** Always extract invariant aggregations, such as `max()` or `sum()` over static collections, outside of loops to ensure O(N) performance.
