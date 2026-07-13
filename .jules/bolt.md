## 2025-02-19 - O(N^2) Regex Line Counting
**Learning:** Using `code[:match.start()].count("\n")` inside a regex iteration loop causes an O(N^2) bottleneck because the string is sliced and scanned from the beginning for every match.
**Action:** Track the line number incrementally by maintaining `current_line` and `last_idx`, using `code.count("\n", last_idx, match.start())` to only scan the string between the last match and the current match.
