## 2024-05-24 - O(N^2) Bottleneck in HTML Report Rendering
**Learning:** During HTML report generation, calculating invariant aggregations like `max(vuln_counts.values())` inside a loop evaluating each vulnerability creates an O(N^2) performance bottleneck, as `max()` is O(N) and runs N times.
**Action:** Always extract static collection aggregations outside of loops in report generators and other large rendering functions to reduce complexity to O(N).
