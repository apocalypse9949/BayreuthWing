## 2024-06-02 - O(N^2) Performance Bottleneck in Line Counting
**Learning:** Using `code[:match.start()].count("\n")` within a regex `finditer` loop causes O(N^2) string slicing and counting, which can significantly degrade performance or cause DoS on large files.
**Action:** Always track line numbers incrementally in `finditer` loops by keeping a `last_idx` and `current_line`, and calculating `current_line += code.count("\n", last_idx, match.start())` for each match.
