## 2024-05-24 - Extracting invariants from loops
**Learning:** Calculating max() over a dictionary's values inside a loop over the same dictionary creates an O(N^2) bottleneck during HTML report generation.
**Action:** Always extract invariant aggregations (like max(), sum()) outside of loops, especially in rendering logic.
