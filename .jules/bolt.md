## 2024-05-24 - HTML Report Rendering O(N^2) Bottleneck
**Learning:** Evaluating `max()` on static dictionary values inside a loop causes an O(N^2) bottleneck, which is particularly severe when rendering HTML reports with large vulnerability lists.
**Action:** Always extract invariant aggregations (like `max()` or `sum()`) over static collections and calculate them outside the loop to optimize rendering loops.
