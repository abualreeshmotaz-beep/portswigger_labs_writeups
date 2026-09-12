# Reflected XSS into HTML Context with Nothing Encoded

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Apprentice
**Category:** Reflected XSS

---

## Problem

The lab's search functionality reflects user input directly back into the HTML response without any encoding or sanitization. This allows an attacker to inject arbitrary HTML/JavaScript that executes in the victim's browser in the context of the vulnerable site.

The goal is to perform a reflected XSS attack that triggers the `alert` function.

---

## Discovery / Exploitation

1. Navigated to the lab's blog search page.
2. Entered a search term and observed that the value was reflected back verbatim inside the page's HTML — with no encoding of special characters (`<`, `>`, `"`, etc.).
3. Since the input lands directly inside the HTML body context (not inside an attribute or a script string), it's possible to inject a new `<script>` tag directly.
4. Confirmed the reflection point by viewing the page source after searching a canary value, verifying no filtering was applied.

---

## Proof of Concept

**Payload used in the search box:**
```html
<script>alert(1)</script>
```

**Steps:**
1. Enter the payload above into the search box.
2. Click "Search".
3. The browser parses the reflected response, encounters the injected `<script>` tag, and executes it — an `alert(1)` popup is triggered.

**Resulting URL (GET-based reflection):**
```
https://YOUR-LAB-ID.web-security-academy.net/?search=<script>alert(1)</script>
```

---

## Remediation

- **Contextual output encoding:** HTML-encode all user-controlled data before reflecting it into an HTML body context (e.g., encode `<`, `>`, `&`, `"`, `'` to their HTML entity equivalents).
- **Content Security Policy (CSP):** Implement a strict CSP (e.g., disallowing inline scripts) as a defense-in-depth measure to mitigate the impact of any XSS that slips through.
- **Input validation:** While not a substitute for output encoding, validating/restricting expected input formats (e.g., alphanumeric search terms) can reduce the attack surface.
- **Use safe DOM APIs:** Avoid directly concatenating user input into raw HTML; use safe methods like `textContent` on the client side, or auto-escaping template engines on the server side.
