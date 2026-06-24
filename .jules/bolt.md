## 2026-06-24 - [Extract Invariant Aggregations in Report Generator]
**Learning:** In the `ReportGenerator` HTML rendering logic, invariant aggregations such as `max(vuln_counts.values())` were being calculated inside loop iterations over vulnerability collections, resulting in unnecessary O(N^2) overhead during report generation.
**Action:** Always extract static aggregations (`max()`, `sum()`) outside of loops, particularly in reporting and templating paths, to maintain O(N) complexity and improve HTML report rendering speed.
