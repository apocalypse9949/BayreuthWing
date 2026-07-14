## 2024-05-01 - Prevent O(N^2) Performance Bottlenecks in Report Generation
**Learning:** Invariant aggregations (like `max()` over static collections) inside loops can cause O(N^2) performance bottlenecks, especially during HTML report rendering where collections might be large.
**Action:** Always extract invariant calculations outside of loops to ensure they are computed only once.
