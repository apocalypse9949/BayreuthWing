## 2026-04-28 - Accessible HTML Chart Components
**Learning:** Visual custom chart components (like HTML bar charts generated in reports) lack semantic meaning for screen readers. Using `role="progressbar"` with `aria-valuenow` on the bars and wrapping rows with a descriptive `aria-label` (while hiding the redundant text elements using `aria-hidden="true"`) creates a significantly better audio representation.
**Action:** Always add semantic `aria` roles (`progressbar`) and values (`aria-valuenow`, `aria-valuemin`, `aria-valuemax`) to custom visual data representation elements.
