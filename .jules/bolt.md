## 2024-05-24 - [Extract invariant aggregations from loops]
**Learning:** Found an O(N^2) performance bottleneck in HTML report generation where max() over a dictionary was recalculated in every iteration of a loop.
**Action:** Extract invariant aggregations like max() or sum() outside of loops to improve rendering performance.
