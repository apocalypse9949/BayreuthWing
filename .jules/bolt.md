## 2024-05-20 - Extract Invariant Aggregations
**Learning:** Calculating aggregations like `max()` over static collections inside a rendering loop creates an O(N^2) performance bottleneck in HTML generation.
**Action:** Always extract and calculate invariant aggregations outside of loops when rendering reports.
