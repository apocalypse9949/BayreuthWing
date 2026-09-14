## 2024-05-30 - Invariant Aggregation in HTML Report
**Learning:** Computing `max()` over static collections inside a loop causes an O(N^2) performance bottleneck, which degrades performance during HTML report rendering.
**Action:** Always extract and calculate invariant aggregations outside of loops.
