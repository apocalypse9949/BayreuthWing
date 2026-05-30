## 2026-05-30 - Invariant Aggregation Loop Bottlenecks
**Learning:** Performing invariant collection aggregations like `max()` or `sum()` inside loops creates hidden O(N^2) performance bottlenecks, especially detrimental in reporting functions iterating over large datasets.
**Action:** Always extract static aggregations over collections outside of loops to maintain O(N) complexity.
