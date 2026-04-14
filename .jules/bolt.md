## 2025-01-08 - Optimized O(N^2) line counting inside Regex matches
**Learning:** Calling `code[:match.start()].count("\n")` inside a regex `finditer` loop causes massive performance degradation on files with many matches because it copies the substring and rescans from index 0 for every match, resulting in $O(M \times N)$ complexity.
**Action:** Always count newlines incrementally between `match.start()` indices (`code.count("\n", last_idx, idx)`) when parsing matches sequentially to achieve $O(N)$ overall complexity.
