## 2024-07-06 - [Extract Invariants from Loops]
**Learning:** Found O(N^2) performance bottleneck in HTML report rendering due to max() being called repeatedly in a loop over static collections.
**Action:** Extract invariant aggregations outside of loops to avoid recalculation.