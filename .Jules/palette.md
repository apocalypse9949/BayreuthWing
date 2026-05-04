## 2026-05-04 - Add ARIA attributes to HTML report bar chart
**Learning:** Custom visual elements (like CSS bar charts) in HTML reports are completely invisible/meaningless to screen readers without proper semantic roles.
**Action:** When implementing or updating custom visual elements, always provide semantic roles (`role="progressbar"`) and relevant ARIA attributes (`aria-valuenow`, `aria-label`, etc.) to ensure accessibility.
