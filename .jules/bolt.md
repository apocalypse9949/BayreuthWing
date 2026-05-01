## 2024-05-01 - O(N^2) String Slicing in Regex Loops
**Learning:** Found an O(N^2) bottleneck during regex scanning where the string was sliced from the beginning for every match (`code[:match.start()].count("\n")`), causing significant performance degradation on large code blocks.
**Action:** Always track line numbers incrementally by utilizing the `start` and `end` arguments of `count()` alongside the previous match's index (e.g., `current_line += code.count('\n', last_idx, match.start())`).
