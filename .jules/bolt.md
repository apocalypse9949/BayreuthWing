## 2024-05-24 - [Extract invariant aggregations in HTML rendering]
**Learning:** Invariant aggregations (like `max()`) over static collections placed inside loops create O(N^2) performance bottlenecks during HTML report rendering.
**Action:** Extract invariant aggregations and calculate them outside the loop to prevent redundant calculations and reduce complexity.
