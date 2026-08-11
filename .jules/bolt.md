## 2024-08-11 - Hoisting loop invariants in HTML report rendering
**Learning:** Extracting invariant aggregations like `max()` over static collections outside of loops prevents O(N^2) performance bottlenecks, especially during HTML report rendering.
**Action:** Always check loops for invariant calculations and hoist them outside the loop.
