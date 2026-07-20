## 2024-07-20 - Extract Invariant Aggregations in Reporting Loops
**Learning:** Evaluated invariant aggregations (like `max()` on static dictionaries) inside loops create unnecessary O(N²) bottlenecks in string/HTML generation paths.
**Action:** Always extract static dataset aggregations to outside the loop scope before iterating.
