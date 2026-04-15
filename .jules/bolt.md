## 2023-10-27 - Incremental Line Counting
**Learning:** String slicing inside a loop (e.g., `code[:match.start()].count("\n")`) can cause catastrophic $O(N^2)$ performance degradation on large codebases.
**Action:** Use incremental updates by keeping track of the `last_pos` and updating the line counter using `code.count("\n", last_pos, start)`. This optimization is universally applicable when dealing with line numbers of consecutive matches in large strings.
