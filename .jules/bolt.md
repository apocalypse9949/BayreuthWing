## 2024-05-24 - HTML Report Render Bottleneck
**Learning:** The HTML report generation in `src/scanner/reporter.py` contained an O(N^2) bottleneck by recalculating the maximum vulnerability count (`max(vuln_counts.values())`) inside the loop for every vulnerability class.
**Action:** Extract invariant aggregations, like max() over static collections, outside of loops to prevent unnecessary recalculation, especially during report rendering which may handle many vulnerability classes.
