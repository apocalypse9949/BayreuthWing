## 2024-05-12 - Custom CSS Visualizations Require ARIA Roles
**Learning:** Custom CSS bar charts used for vulnerability breakdown in the HTML report are interpreted as empty `div`s by screen readers. This is a common accessibility trap in static security reports.
**Action:** Always add `role="progressbar"` along with `aria-valuenow`, `aria-valuemin`, and `aria-valuemax` attributes to custom CSS visualizations to ensure semantic meaning.
