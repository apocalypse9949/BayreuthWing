## 2024-05-24 - Extracted invariant aggregations in loops
**Learning:** Found O(N^2) bottleneck in `_generate_html` report generation where `max()` over static collections was being recalculated on every loop iteration.
**Action:** Always extract invariant aggregations (`max()`, `sum()`, etc.) over static collections outside of loops to prevent unnecessary O(N^2) operations, especially in reporting and rendering logic.
