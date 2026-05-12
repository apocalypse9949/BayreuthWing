## 2025-03-01 - O(N^2) Bottleneck in HTML Reporter
**Learning:** Invariant aggregations like `max()` over static collections were placed inside loops during HTML template rendering, creating an O(N^2) bottleneck.
**Action:** Always extract invariant calculations from template loops over static collections to prevent rendering slowdowns on large data sets.
