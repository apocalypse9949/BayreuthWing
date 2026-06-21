## 2024-10-25 - O(N^2) String Slicing and Invariant Aggregation Bottlenecks
**Learning:** Slicing a large string from the beginning for every regex match (`code[:match.start()].count('\n')`) and recalculating aggregations like `max()` inside loops causes O(N^2) performance bottlenecks.
**Action:** Track line numbers incrementally using `code.count('\n', last_idx, match.start())` and extract invariant aggregations outside of loops to maintain O(N) complexity.
