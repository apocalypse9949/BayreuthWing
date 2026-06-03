## 2024-05-24 - HTML Report Generator O(N²) Bottleneck
**Learning:** Invariant aggregations (like `max_count = max(vuln_counts.values())`) inside loops, especially during the HTML rendering of large vulnerability lists, cause O(N²) performance degradation.
**Action:** Always extract static collection aggregations outside of rendering loops to ensure O(N) performance.