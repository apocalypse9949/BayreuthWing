## 2024-05-15 - HTML Report Rendering Bottleneck
**Learning:** Invariant aggregations over static collections within loops cause O(N^2) performance bottlenecks during HTML report rendering.
**Action:** Always extract and calculate operations like `max()` or `sum()` outside of the loop when the underlying collection doesn't change.
