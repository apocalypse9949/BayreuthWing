## 2024-07-04 - O(N^2) String Slicing in Regex Line Tracking
**Learning:** For regex scanning in the BAYREUTHWING engine, avoid O(N^2) performance bottlenecks and ReDoS/DoS vulnerabilities by tracking line numbers incrementally (e.g., code.count('\n', last_idx, match.start())) instead of slicing the string from the beginning for each match.
**Action:** Always use an incremental index (`last_idx`) and `current_line` counter when processing iterative matches via `re.finditer` to prevent linear time string copying in tight loops.
