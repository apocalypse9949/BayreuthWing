## 2026-04-17 - [Fix O(N^2) regex DoS in Rule Engine]
**Vulnerability:** O(N^2) complexity in tracking line numbers for regex matches allowed DoS/ReDoS vectors when parsing large or untrusted codebases.
**Learning:** String slicing and re-counting from the beginning of strings for each match creates massive overhead for regex engines parsing unvalidated user code.
**Prevention:** Use an incremental line counting approach (e.g. `code.count('\n', last_idx, match.start())`) to ensure O(N) complexity in regex processing.
