## 2026-04-17 - Incremental Line Counting for Regex Scans
**Learning:** Found an O(N^2) performance bottleneck in the static rules engine `matches` method due to slicing the file contents from the beginning on every match to count newlines. This affects large codebases specifically.
**Action:** Always track `last_idx` and use `code.count('\n', last_idx, match.start())` when iterating over regex matches to find line numbers incrementally.
