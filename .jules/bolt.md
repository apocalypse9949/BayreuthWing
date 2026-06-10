## 2024-05-18 - Extract Invariant Aggregations Outside Loops
**Learning:** Invariant aggregations, such as `max()` or `sum()`, placed inside loops over static collections (like generating HTML reports) create an O(N^2) performance bottleneck.
**Action:** Always extract and calculate invariant aggregations outside of the loop to maintain O(N) performance.