## 2026-07-07 - Extract invariant aggregations in rendering loops
**Learning:** Invariant aggregations (like max() over static collections) inside loops can cause severe O(N^2) performance bottlenecks, especially in HTML template generation.
**Action:** Always extract static collection aggregations outside of loop bodies before iterating.
