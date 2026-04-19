## 2025-03-01 - Prevent O(N^2) Line Counting Performance Bottleneck
**Learning:** For regex scanning in the BAYREUTHWING engine, using `code[:match.start()].count("\n")` causes an O(N^2) performance bottleneck because it slices the string from the beginning for each match. This can lead to ReDoS/DoS vulnerabilities on large files.
**Action:** Avoid O(N^2) bottlenecks by tracking line numbers incrementally (e.g., `code.count('\n', last_idx, match.start())`) instead of slicing the string from the beginning for each match.
