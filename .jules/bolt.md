## 2025-03-05 - O(N^2) Performance Bottleneck in HTML Report Generation
**Learning:** Found a performance bottleneck in the HTML report generator where `max(vuln_counts.values())` was calculated inside the loop rendering each chart row. For reports with many vulnerability types, this causes redundant iterations over the entire values list, making the complexity O(N^2) relative to the number of unique vulnerability types.
**Action:** Extract invariant aggregations like `max()` or `sum()` over static collections outside of loops to prevent unnecessary recalculations.
