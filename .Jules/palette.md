## 2024-05-24 - Accessible Custom Bar Charts
**Learning:** Custom CSS bar charts in the HTML report lack screen reader context and read as disjointed text. Grouping them with `role='listitem'` and `aria-hidden='true'` on the visual components creates a unified, accessible label for custom data visualizations.
**Action:** Apply `role='listitem'` and an explicit `aria-label` to custom chart rows, while hiding the inner visual DOM elements (`aria-hidden='true'`) from screen readers.
