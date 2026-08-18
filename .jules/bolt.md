## 2024-05-18 - [Optimize chart rendering loop]
**Learning:** O(N^2) bottlenecks can occur in HTML report rendering loops when invariant aggregations like max() are computed inside the loop.
**Action:** Ensure invariant aggregations are extracted and calculated outside of loops to improve performance.
