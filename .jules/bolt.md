## 2024-05-24 - HTML Report O(N^2) Bottleneck
**Learning:** Found an O(N^2) bottleneck in the HTML report generator (`_generate_html` in `src/scanner/reporter.py`) where `max(vuln_counts.values())` was calculated inside the iteration loop over findings. Since `vuln_counts` is static during rendering, this creates unnecessary overhead for large reports.
**Action:** Always extract invariant aggregations (like `max()`, `sum()`) outside of loops during report rendering or string interpolation to maintain O(N) complexity.
