## 2024-10-25 - HTML Report O(N²) Bottleneck
**Learning:** Found an O(N²) performance bottleneck during HTML report generation where `max()` was called on a static collection inside a loop.
**Action:** Always extract invariant aggregations (like `max()` or `sum()`) outside of loops to prevent unnecessary recalculation.
