## 2025-02-24 - HTML Report O(N^2) Bottleneck
**Learning:** Calculating invariant aggregations, like `max(vuln_counts.values())`, inside a `for` loop over `vuln_counts.items()` creates an unnecessary O(N^2) complexity that scales poorly for large datasets, especially when rendering HTML reports.
**Action:** Always extract invariant aggregations over static collections to be calculated once outside the loop before beginning iterations.
