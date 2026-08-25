## 2026-08-25 - [O(N^2) Bottleneck in Report Generation]
**Learning:** Invariant aggregations (like `max()`) inside rendering loops cause O(N^2) performance bottlenecks, which is particularly problematic when rendering HTML reports for scans with numerous vulnerability types.
**Action:** Always extract static collection calculations outside of the loop before iterating.
