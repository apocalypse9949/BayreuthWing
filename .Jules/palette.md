## 2024-05-06 - Accessible CSS Bar Charts
**Learning:** Custom CSS bar charts in HTML reports are invisible to screen readers, depriving visually impaired users of important data context.
**Action:** Always add semantic roles (like `role="progressbar"`) and relevant ARIA attributes (`aria-valuenow`, `aria-label`, `aria-valuemin`, `aria-valuemax`) to custom visual elements to ensure they are accessible.
