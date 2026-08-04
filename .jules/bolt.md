## 2024-08-04 - Fix O(N^2) Performance Bottleneck in HTML Report Rendering
**Learning:** Found an O(N^2) performance issue in HTML report generation because an invariant aggregation (`max(vuln_counts.values())`) was calculated inside a loop over vulnerability counts.
**Action:** Always extract static aggregations like `max()` or `sum()` over collections outside of loops to prevent unnecessary recalculations, especially when generating large reports.
