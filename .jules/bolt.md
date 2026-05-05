## 2024-05-05 - Invariant Aggregation in Render Loops
**Learning:** Calculating aggregations like `max()` over static collections inside rendering loops creates an O(N^2) performance bottleneck, especially as the number of vulnerabilities grows in the HTML report.
**Action:** Always extract and calculate invariant aggregations outside of loops before iterating over collections.
