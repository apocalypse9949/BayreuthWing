## 2024-05-08 - O(N) max inside loop
**Learning:** Extracted invariant max() from a rendering loop in src/scanner/reporter.py to prevent O(N^2) complexity.
**Action:** Always compute invariant aggregations over static collections outside loops.
