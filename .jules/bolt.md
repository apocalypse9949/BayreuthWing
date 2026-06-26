## 2025-05-18 - Extracting invariant aggregations from loops
**Learning:** In Python, computing aggregations like `max()` over static collections within a loop results in an O(N^2) performance bottleneck, especially problematic when dealing with HTML report rendering containing large payload sets.
**Action:** Always extract invariant aggregations out of loops before rendering to ensure linear O(N) execution time.
