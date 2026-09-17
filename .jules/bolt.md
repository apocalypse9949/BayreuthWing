## 2025-02-14 - Optimize HTML report rendering
**Learning:** Avoid O(N^2) performance bottlenecks in loops (especially during HTML report rendering) by ensuring that invariant aggregations, such as `max()` or `sum()` over static collections, are extracted and calculated outside of the loop.
**Action:** Always check loop bodies for calculations that depend on static collections and hoist them before the loop.
