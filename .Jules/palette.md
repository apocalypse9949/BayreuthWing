## 2026-04-24 - Accessible HTML Bar Charts
**Learning:** Custom CSS bar charts in HTML reports are invisible to screen readers unless semantic ARIA roles and values are applied.
**Action:** Always add `role="progressbar"` with `aria-valuenow`, `aria-valuemin`, and `aria-valuemax` to custom visual progress/bar elements.
