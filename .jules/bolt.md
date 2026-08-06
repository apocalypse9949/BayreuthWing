## 2024-05-18 - HTML Rendering Performance
**Learning:** Avoid O(N^2) bottlenecks in loops (especially during HTML report rendering) by ensuring that invariant aggregations, such as `max()` over static collections, are extracted and calculated outside of the loop.
**Action:** Extract invariant calculations outside loops before rendering templates.
