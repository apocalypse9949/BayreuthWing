## 2026-04-29 - Accessible Data Visualizations in HTML Reports
**Learning:** Custom CSS bar charts in generated HTML reports are invisible to screen readers, leaving visually impaired users with unassociated labels and numbers.
**Action:** Always add `role="progressbar"`, `aria-valuenow`, `aria-valuemin`, and `aria-valuemax` to custom chart bars, and use `aria-hidden="true"` on redundant visual text to provide a clean screen reader experience.
