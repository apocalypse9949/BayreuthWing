## 2024-04-21 - Optimize Regex Line Counting
**Learning:** Avoid O(N^2) string slicing in regex line counting `code[:match.start()].count("\n")`.
**Action:** Use incremental line tracking using `current_line += code.count("\n", last_idx, match.start())` to avoid DoS on large files.
