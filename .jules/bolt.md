## 2024-05-24 - Extract Invariant Aggregations in HTML Rendering
**Learning:** Invariant aggregations like `max()` over static collections inside loops cause O(N^2) performance bottlenecks during HTML report rendering in this architecture.
**Action:** Always extract and calculate invariant aggregations outside of rendering loops to ensure O(N) performance.