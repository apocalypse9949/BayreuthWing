## 2026-04-15 - Line number calculation O(N^2) anti-pattern
**Learning:** Calculating line numbers in regex `finditer` loops using `code[:match.start()].count('\n') + 1` creates a massive O(N^2) performance bottleneck due to continuous string slicing and recounting.
**Action:** Always use an incremental line counter approach, tracking the last match index and counting newlines only between `last_idx` and `current_match.start()`.
