## 2025-02-24 - HTML Report Loop Bottleneck
**Learning:** Invariant aggregations like `max()` over static collections placed inside rendering loops cause an O(N^2) performance bottleneck during HTML report generation, scaling poorly with many vulnerability classes.
**Action:** Always extract invariant aggregations out of loops before rendering templates.
