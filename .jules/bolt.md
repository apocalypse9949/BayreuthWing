## 2024-05-24 - [Avoid O(N^2) bottlenecks in HTML report rendering]
**Learning:** Repeatedly calculating invariant aggregations like `max(vuln_counts.values())` inside the HTML report rendering loop creates an O(N^2) performance bottleneck.
**Action:** Extract invariant aggregations and calculate them outside the loop to ensure O(N) performance.
