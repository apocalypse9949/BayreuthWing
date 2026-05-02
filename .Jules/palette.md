## 2026-05-02 - Custom CSS Bar Chart Accessibility
**Learning:** The reporting engine's custom CSS bar charts (`chart-bar-container`) are a recurring UI pattern in the HTML templates but inherently lack screen reader visibility.
**Action:** Always apply `role="progressbar"`, `aria-valuenow`, and `aria-valuemax` to custom CSS bar charts in the BAYREUTHWING reporter to ensure visual data is accessible.
