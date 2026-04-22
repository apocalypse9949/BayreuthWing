## 2026-04-22 - Screen Reader Unfriendly Emojis in Reports
**Learning:** The HTML reporter uses decorative emojis (📄, 📍, 🏷️, 📋, 🔍) inline with finding details. Screen readers loudly interpret these as "page facing up" or "round pushpin", making the critical security report extremely noisy and frustrating for non-sighted users.
**Action:** Always wrap report emojis in `<span aria-hidden="true" title="...">` to hide them from assistive tech while providing tooltips for sighted users. Then apply an overarching `aria-label` to the parent container for clean screen reader dictation.
