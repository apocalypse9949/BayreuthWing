## 2024-07-28 - O(N^2) String Slicing in Regex Scanning
**Learning:** Slicing the entire string from the beginning for each regex match (e.g., `code[:match.start()].count('\n')`) creates an O(N^2) performance bottleneck, especially on large files with many matches.
**Action:** Always track line numbers incrementally (e.g., `code.count('\n', last_idx, match.start())`) to avoid unnecessary allocations and maintain O(N) complexity during scanning.
