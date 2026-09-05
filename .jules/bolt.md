## 2025-05-19 - O(N^2) bottlenecks in string formatting
**Learning:** Found an O(N^2) bottleneck during HTML report rendering caused by invariant aggregations like `max()` over static collections being performed repeatedly inside a loop.
**Action:** Extract and calculate invariant aggregations like `max()` or `sum()` over static collections outside of loops.
