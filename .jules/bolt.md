## 2024-05-24 - O(N^2) Performance Bottleneck in HTML Report Generation
**Learning:** Found an O(N^2) performance bottleneck in `src/scanner/reporter.py` during HTML report rendering because `max(vuln_counts.values())` was being calculated inside a loop for each item. Invariant aggregations over static collections in loops cause severe slowdowns when the collection grows large.
**Action:** Extract invariant aggregations, such as `max()` or `sum()`, outside of loops to ensure O(N) complexity.
