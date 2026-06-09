## 2026-06-09 - Extracting Invariants from Loops
**Learning:** Invariant aggregations like `max()` over static collections inside loops cause O(N^2) bottlenecks, particularly problematic during HTML report rendering with many vulnerability counts.
**Action:** Always extract static collection aggregations outside loops before iterating to improve performance and avoid N^2 scaling issues.