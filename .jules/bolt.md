## 2024-05-20 - Incremental Line Counting for Regex
**Learning:** Using `code[:match.start()].count("\n")` inside a regex loop creates an O(N^2) bottleneck for large files because it re-slices and re-counts from the beginning of the string for every match.
**Action:** Track the line numbers incrementally by calculating `current_line += code.count("\n", last_idx, match.start())` and updating `last_idx = match.start()` to avoid the O(N^2) overhead in regex-heavy scanning engines like BAYREUTHWING.
