## 2024-05-30 - Extract Loop Invariants in HTML Rendering
**Learning:** Performing aggregations like `max()` on static collections inside a rendering loop creates an unnecessary O(N^2) bottleneck.
**Action:** Always extract invariant calculations (e.g., `max_count = max(vuln_counts.values())`) outside of loops to ensure O(N) complexity during report generation.
