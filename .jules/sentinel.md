## 2024-05-24 - HTML Reporter XSS
**Vulnerability:** XSS vulnerability in HTML report generation due to unescaped user-controlled inputs in f-string interpolation.
**Learning:** Using Python f-strings to generate HTML without properly escaping variables (like vulnerability_name, filepath, matched_text) can lead to XSS if those values are user-controlled.
**Prevention:** Always use `html.escape()` on user-controlled data before interpolating it into HTML templates, or use a proper templating engine like Jinja2.
