## 2026-05-10 - Accessible CSS Bar Charts
**Learning:** Custom visual data representations like CSS-only bar charts are completely invisible to screen readers unless semantic HTML attributes are applied. They require explicit ARIA roles (progressbar) and values to be read correctly and provide equitable access.
**Action:** Always add role='progressbar', aria-valuenow, aria-valuemin, aria-valuemax, and aria-label when implementing custom visual data representations like CSS progress bars.
