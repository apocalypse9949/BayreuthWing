## 2024-10-18 - Extracted Invariant Aggregation in HTML Rendering
**Learning:** Found an O(N^2) performance bottleneck in HTML report generation where `max()` was repeatedly called inside a loop over vulnerability counts. Invariant aggregations over static collections in Python must be extracted to prevent unnecessary overhead.
**Action:** Always compute invariant aggregations like `max()` or `sum()` outside of loops, especially in rendering or data processing pipelines.
