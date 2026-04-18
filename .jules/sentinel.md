## 2026-04-18 - Fix O(N^2) ReDoS/DoS Vulnerability in Regex Scanning
**Vulnerability:** Found O(N^2) DoS bottleneck due to repeated string slicing and counting newlines on large code inputs.
**Learning:** Calling code[:match.start()].count('\n') in a loop over regex matches causes quadratic time complexity, leading to DoS vulnerabilities.
**Prevention:** Track line numbers incrementally using last index and current line count (e.g., code.count('\n', last_idx, match.start())).
