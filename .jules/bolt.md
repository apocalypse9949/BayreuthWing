## 2026-07-05 - Extracted invariant aggregation from loop
**Learning:** Calculating max() over a dictionary's values inside a loop iterating over that same dictionary's items causes an O(N^2) performance bottleneck, especially problematic during HTML report rendering with many vulnerability classes.
**Action:** Always extract invariant aggregations (like max, min, sum over static collections) outside of loops to maintain O(N) complexity.
