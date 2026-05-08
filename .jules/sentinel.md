## 2024-05-24 - Fix XSS in HTML Report Generation
**Vulnerability:** Untrusted inputs (such as file paths and matched code) were interpolated directly into the HTML report strings without sanitization.
**Learning:** Python f-strings in HTML templates are highly susceptible to XSS if not properly escaped, and native imports like `html` can be shadowed by local variable names causing runtime errors.
**Prevention:** Always sanitize untrusted data using `html.escape()` when constructing HTML, and use specific variable names like `html_content` to avoid shadowing standard library modules.
