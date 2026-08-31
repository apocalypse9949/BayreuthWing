## 2024-05-18 - Loop Invariant Extraction
**Learning:** Extracted `max()` call from within a loop during HTML report generation in `src/scanner/reporter.py`. Failing to extract invariant aggregations over static collections inside loops can cause O(N^2) bottlenecks.
**Action:** Always verify loop logic and extract invariant expressions outside the loop to optimize performance.
