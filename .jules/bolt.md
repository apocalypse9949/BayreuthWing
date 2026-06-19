## 2024-06-19 - O(N^2) Line Counting DoS
**Learning:** For regex scanning in the BAYREUTHWING engine, avoid O(N^2) performance bottlenecks and ReDoS/DoS vulnerabilities by tracking line numbers incrementally (e.g., code.count('\n', last_idx, match.start())) instead of slicing the string from the beginning for each match.
**Action:** Always use incremental counters for counting lines during regex iterations.
