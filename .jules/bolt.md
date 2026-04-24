## 2024-05-24 - [Preventing O(N^2) String Slicing in Regex Scanning]
**Learning:** [Using `code[:match.start()].count('\n')` inside a `finditer` loop creates an O(N^2) bottleneck on large files because it allocates and scans a new string slice from the beginning for each match.]
**Action:** [Track line numbers incrementally using `code.count('\n', last_idx, match.start())` to avoid repeated full string scanning and reduce time complexity to O(N).]
