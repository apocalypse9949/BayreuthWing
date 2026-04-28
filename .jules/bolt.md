## 2024-04-28 - Avoid O(N^2) String Slicing for Line Counting
**Learning:** Computing line numbers by slicing a string from the beginning for every regex match (e.g., `code[:match.start()].count("\n")`) creates an O(N^2) performance bottleneck when parsing large files with many matches.
**Action:** Track line numbers incrementally per pattern loop by using `code.count('\n', last_idx, match.start())` and updating `last_idx = match.start()` and `current_line`.
