## 2024-08-14 - Optimize HTML report max calculation
**Learning:** Avoid O(N^2) bottlenecks in loops by extracting invariant aggregations.
**Action:** Ensure that operations like `max()` over static collections are calculated outside of loops.
