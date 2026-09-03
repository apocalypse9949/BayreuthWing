## 2024-09-03 - Extract max() from rendering loops
**Learning:** Found an O(N^2) performance bottleneck in the HTML report rendering loop where `max(vuln_counts.values())` was being calculated on every iteration instead of being pre-calculated.
**Action:** Always extract invariant aggregations like `max()` or `sum()` over static collections outside of loops, especially in rendering logic.
