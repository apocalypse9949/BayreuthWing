## 2024-04-27 - Avoid O(N^2) in Regex Line Counting
**Learning:** Using `code[:match.start()].count("\n")` inside a regex matching loop creates an $O(N^2)$ performance bottleneck and ReDoS risk, because the entire string is sliced and scanned for newlines on every match.
**Action:** Use incremental tracking `current_line += code.count("\n", last_idx, match.start())` and update `last_idx = match.start()` to keep it $O(N)$.
