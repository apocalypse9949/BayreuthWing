## 2024-05-13 - Extract invariant aggregations in HTML reporter
**Learning:** Evaluating `max()` inside a loop over static collections in HTML report rendering introduces an O(N^2) performance bottleneck, especially for results with many distinct vulnerability types.
**Action:** Always extract invariant aggregations (like `max()` or `sum()`) outside the loop to ensure O(N) linear time complexity.
