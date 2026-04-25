## 2024-05-23 - O(N^2) Regex Line Counting Bottleneck
**Learning:** Using `code[:match.start()].count("\n")` inside a regex matching loop creates an O(N^2) performance bottleneck when parsing large files, causing severe slowdowns.
**Action:** Always track line numbers incrementally (e.g., `current_line += code.count('\n', last_idx, match.start())`) to keep time complexity at O(N) during regex scanning.
