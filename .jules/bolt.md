## 2026-05-18 - Extract invariant aggregations from loops
**Learning:** Found an O(N^2) bottleneck during HTML report rendering where `max()` was called on the entire vulnerability counts dictionary inside the rendering loop.
**Action:** Always calculate invariants like `max()` or `sum()` over static collections before entering loops to maintain O(N) complexity.
