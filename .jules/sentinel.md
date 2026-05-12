## 2025-02-23 - HTML Reporting XSS Vulnerability
**Vulnerability:** Found unescaped user-controlled values being interpolated into HTML report templates in `src/scanner/reporter.py`. Fields like `f['message']`, `f['matched_text']`, and `results.get('target')` could execute scripts if a target repository has intentionally crafted filenames or code snippets.
**Learning:** Even internal reporting tools are susceptible to XSS if they render untrusted data (the code being scanned).
**Prevention:** Always use `html.escape()` when manually interpolating values into HTML strings, or use a proper templating engine with auto-escaping.
