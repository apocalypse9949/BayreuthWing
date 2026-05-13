## 2024-05-13 - [Semantic ARIA Roles for CSS Bar Charts]
**Learning:** Pure CSS bar charts used for data visualization are invisible to screen readers without specific ARIA attributes.
**Action:** Always add `role="progressbar"`, `aria-valuenow`, `aria-valuemin`, `aria-valuemax`, and `aria-label` to custom visual data elements to ensure meaningful context for assistive technologies.
