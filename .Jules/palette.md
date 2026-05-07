## 2024-05-06 - ARIA attributes for CSS Bar Charts
**Learning:** Custom CSS visual components (like bar charts representing data distributions) are completely invisible to screen readers without semantic roles and ARIA attributes.
**Action:** Always add `role="progressbar"`, `aria-valuenow`, `aria-valuemin`, `aria-valuemax`, and `aria-label` to custom CSS charts/graphs.
