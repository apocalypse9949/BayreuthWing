## 2024-05-15 - HTML Report Rendering O(N^2) Bottleneck
**Learning:** Found an O(N^2) performance bottleneck in HTML report generation where `max()` over static collections was being recalculated inside a loop for every chart item rendering.
**Action:** Always extract and calculate invariant aggregations (like `max()` or `sum()`) outside of loops, especially during intensive string concatenation or rendering operations.
