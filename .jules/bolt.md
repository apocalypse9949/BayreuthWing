## 2024-06-28 - Extract invariant aggregation from loop in HTML report generator
**Learning:** Found an O(N^2) performance bottleneck in `src/scanner/reporter.py` during HTML report generation. The `max(vuln_counts.values())` expression was being recalculated inside the loop for every vulnerability, making it extremely slow for large numbers of vulnerabilities (e.g. from ~2.8s to ~0.04s for 10k items).
**Action:** Always extract invariant aggregations, such as `max()`, `sum()`, etc., out of loops.
