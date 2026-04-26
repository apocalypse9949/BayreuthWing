## 2024-04-26 - O(N^2) DoS Vulnerability in Regex Line Counting
**Vulnerability:** Code used `line = code[:match.start()].count("\n") + 1` in loops iterating over regex matches (`re.finditer`). On large files with many matches, this caused O(N^2) string slicing and counting operations, leading to Denial of Service (DoS).
**Learning:** The O(N^2) pattern existed because it was a simple way to find the line number of a match, but the performance implications on large files were not considered.
**Prevention:** Always track line numbers incrementally by keeping state between matches: `current_line += code.count('\n', last_idx, match.start())` and `last_idx = match.start()`.
