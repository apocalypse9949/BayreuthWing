## 2026-06-30 - Extract Invariant Aggregations in HTML Rendering
**Learning:** Found an O(N^2) bottleneck in HTML report rendering (`src/scanner/reporter.py`) where `max(vuln_counts.values())` was unnecessarily calculated inside the loop over the same static collection.
**Action:** Always extract invariant aggregations (e.g., `max()`, `sum()`) out of rendering loops to prevent performance degradation on large datasets.
