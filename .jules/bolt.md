## 2024-07-25 - HTML Reporter O(N^2) Bottleneck
**Learning:** Found an O(N^2) bottleneck in the HTML report generator (`_generate_html`) where `max()` was called on the entire dictionary values array during every iteration of a loop rendering the vulnerability chart.
**Action:** Extract invariant aggregate operations (like `max()` or `sum()`) out of loops to prevent unnecessary recalculations.
