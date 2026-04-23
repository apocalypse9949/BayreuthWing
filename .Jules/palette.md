## 2026-04-23 - Accessibility of Visual Charts in Static Reports
**Learning:** Custom `div`-based charts (like horizontal bar graphs) are completely ignored or read confusingly by screen readers unless properly semantically tagged.
**Action:** Always add `role="progressbar"` and `aria-valuenow`/`aria-valuemin`/`aria-valuemax` to visual data bars, and hide redundant text nodes using `aria-hidden="true"` to create a smooth auditory experience.
