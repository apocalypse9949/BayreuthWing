## 2024-07-03 - Avoid O(N^2) performance bottlenecks in regex line counting
**Learning:** Slicing strings from the beginning for every regex match (`code[:match.start()].count('\n') + 1`) causes O(N^2) memory and time complexity for line counting, causing significant performance degradation on large files with many matches.
**Action:** Track line numbers incrementally using `code.count('\n', last_idx, match.start())` and update `last_idx` to avoid unnecessary string allocations and reduce complexity to O(N).
