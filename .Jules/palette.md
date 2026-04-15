## 2026-04-15 - Adding ARIA Attributes to HTML String Templates
**Learning:** Default string templates converting terminal output or static data to HTML often lack semantic accessibility for screen readers. Tools generate charts and cryptic emojis that break screen reader experiences without explicit ARIA definitions.
**Action:** Add `role`, `aria-valuenow`, and `aria-label` attributes to visual chart divs, and wrap decorative emojis with `aria-hidden="true"` and informative titles in generated HTML reports to make security reports accessible.
