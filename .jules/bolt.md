## 2024-10-24 - HTML Report O(N^2) Bottleneck
**Learning:** Found an O(N^2) performance bottleneck in the HTML report generator (`_generate_html`) where `max(vuln_counts.values())` was being recalculated inside a loop for every chart item.
**Action:** Always extract invariant aggregations (like `max()` or `sum()`) over static collections outside of loops to prevent O(N^2) degradation.
