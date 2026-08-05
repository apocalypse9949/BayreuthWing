## 2024-08-05 - Avoid invariant aggregation inside loops
**Learning:** Computing aggregates like `max()` over static collections inside a loop causes O(N^2) time complexity, especially problematic during HTML report rendering where collections might grow.
**Action:** Always extract invariant calculations such as `max()` or `sum()` outside of loops.
