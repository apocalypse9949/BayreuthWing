## 2026-05-03 - Accessible Data Visualizations
**Learning:** Custom CSS bar charts in HTML reports are invisible to screen readers without semantic roles.
**Action:** Always add `role="progressbar"`, `aria-valuenow`, `aria-valuemin`, and `aria-valuemax` to custom chart elements to ensure they are interpreted as data visualizations by assistive technologies.
