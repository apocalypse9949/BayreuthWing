## 2024-07-22 - Extract invariant aggregations from loops
**Learning:** Invariant aggregations, such as max() or sum() over static collections, evaluated inside loops cause an O(N^2) performance bottleneck, especially noticeable during HTML report rendering.
**Action:** Always extract static collection aggregations and calculate them outside of loops.
