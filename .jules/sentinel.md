## 2026-05-03 - XSS in HTML Report Generation
**Vulnerability:** Unescaped raw code snippets (matched_text) concatenated directly into HTML reports.
**Learning:** Security tools are often targets themselves. Code being scanned must be treated as untrusted user input when rendering reports.
**Prevention:** Always use `html.escape()` when rendering potentially untrusted strings in HTML templates.