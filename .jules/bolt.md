## 2024-05-24 - Extracting Invariant Aggregations
**Learning:** Invariant aggregations like `max()` or `sum()` over static collections inside rendering loops create O(N^2) bottlenecks, particularly in HTML report generation loops (e.g., chart rendering in `reporter.py`).
**Action:** Always extract static aggregations outside the loop body to prevent redundant O(N) recalculations and ensure O(N) instead of O(N^2) complexity.
