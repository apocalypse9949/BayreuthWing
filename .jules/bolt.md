## 2024-05-18 - HTML Report Generation O(N^2) Bottleneck
**Learning:** Invariant aggregations inside rendering loops cause O(N^2) performance bottlenecks.
**Action:** Always extract static aggregations outside of loops.
