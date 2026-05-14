## 2024-05-14 - Fix XSS in HTML Report
**Vulnerability:** Cross-Site Scripting (XSS) vulnerability in HTML report generation because string properties of findings were injected without HTML escaping.
**Learning:** Formatting HTML templates directly with f-strings requires explicit sanitization of all untrusted inputs to prevent script injection.
**Prevention:** Always use `html.escape()` for user-controlled data when rendering HTML templates manually, or use a proper templating engine with auto-escaping.
