## 2024-05-18 - HTML Reporter Render Loop O(N^2) Aggregation
**Learning:** O(N^2) performance bottleneck found in HTML reporter where `max()` over static collections is executed redundantly inside loop during HTML rendering.
**Action:** Extract loop-invariant computations like `max(vuln_counts.values())` out of loops to maintain linear execution time, especially for report generation over potentially large vulnerability data sets.
