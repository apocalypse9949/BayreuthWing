## 2024-05-24 - Optimize regex line counting performance to O(N)
**Learning:** Repeated string slicing to count newlines for regex match lines (`code[:match.start()].count("\n")`) scales quadratically O(N^2).
**Action:** Track line numbers incrementally using `current_line += code.count('\n', last_idx, match.start())` to optimize line resolution for regex matches.