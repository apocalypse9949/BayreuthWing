## 2024-05-14 - Screen Reader Compatibility with Decorative Emojis
**Learning:** HTML reports generated via Python templates often contain decorative emojis (like 📄, 📍) that screen readers will read aloud natively (e.g., "page facing up"), creating a very noisy and poor experience for visually impaired users.
**Action:** Always wrap decorative emojis or icon glyphs in `<span aria-hidden="true">` when generating HTML via Python to ensure they are ignored by assistive technologies, keeping the focus on the actual content.
