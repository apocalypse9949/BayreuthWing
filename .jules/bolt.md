## 2026-06-07 - [O(N^2) Bottleneck in HTML Report Generation]
**Learning:** Calling max() on the entire vuln_counts dictionary inside a loop over the same dictionary creates a severe O(N^2) performance bottleneck, drastically slowing down HTML report generation for scans with many findings.
**Action:** Calculate the invariant max() value once outside the loop before generating chart items.