## 2024-05-24 - Extracting Loop Invariants for HTML Rendering
**Learning:** Repeatedly calling max() on a dictionary's values inside a loop over the same dictionary creates an O(N^2) operation, which can severely impact performance during HTML report generation for large datasets.
**Action:** Always extract invariant aggregations (like max() or sum()) over static collections before entering loops.
