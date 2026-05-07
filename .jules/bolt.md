## 2024-05-24 - [Extract Invariant Aggregations from Loops]
**Learning:** Found an O(N^2) bottleneck in `src/scanner/reporter.py` during HTML report rendering where `max(vuln_counts.values())` was calculated inside the loop for each vulnerability type.
**Action:** Extract invariant aggregations over static collections outside of loops to improve performance from O(N^2) to O(N).
