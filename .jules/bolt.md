## 2024-05-23 - O(N^2) String Slicing in Regex Finditer
**Learning:** Using `code[:match.start()].count("\n")` inside a regex `finditer` loop causes O(N^2) performance degradation and high memory allocation on large files, because a new substring is created for every match.
**Action:** Always track line numbers incrementally across matches using `current_line += code.count("\n", last_idx, match.start())` and update `last_idx = match.start()`.
