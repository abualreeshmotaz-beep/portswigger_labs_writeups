# Reflected XSS into a JavaScript String with Angle Brackets HTML Encoded

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Apprentice
**Category:** Reflected XSS

---

## Problem

The lab's search query tracking functionality reflects user input directly inside a JavaScript string literal within an inline `<script>` block. Angle brackets (`<` and `>`) are HTML-encoded before being reflected, which prevents injecting a new HTML tag — but this encoding is irrelevant to the actual injection context here, since the reflection point is inside a JavaScript string, not the HTML body or an HTML attribute.

The goal is to perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

---

## Discovery / Exploitation

1. Submitted a random alphanumeric canary string into the search box.
2. Intercepted the search request in Burp Suite and sent it to Burp Repeater.
3. Observed that the canary string was reflected directly inside a JavaScript string literal, in a pattern resembling:
   ```javascript
   var searchTerms = 'CANARY_VALUE';
   document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
   ```
4. Confirmed angle brackets were HTML-encoded in the response (irrelevant here, since this isn't an HTML injection context).
5. Recognized that the value sits inside a `'...'` string assigned to `searchTerms`, evaluated as live JavaScript when the page loads — meaning the relevant "escape characters" are JavaScript syntax characters (`'`, `;`), not HTML characters (`<`, `>`, `"`).
6. Note: `encodeURIComponent()`, seen applied later in the same script to `searchTerms` when building the `document.write` markup, protects the *output* of that later `document.write` call — it does not protect the *initial* reflection of the raw search term into the `var searchTerms = '...'` string itself, which is where the actual injection point is.

---

## Proof of Concept

**Payload used in the search box:**
```
'-alert(1)-'
```

**Resulting injected script:**
```javascript
var searchTerms = ''-alert(1)-'';
```

**Steps:**
1. Enter the payload above into the search box (or modify the `search` parameter directly in Burp Repeater).
2. The browser parses the resulting line as: an empty string `''`, minus `alert(1)`, minus an empty string `''` — a valid (if nonsensical) JavaScript expression that still executes `alert(1)` as part of evaluating it.
3. Right-click the page, select "Copy URL" (with the payload in the `search` query parameter), and paste that URL into the browser.
4. On page load, the injected script executes automatically, and `alert(1)` fires — no additional user interaction is required.

**Resulting URL:**
```
https://YOUR-LAB-ID.web-security-academy.net/?search='-alert(1)-'
```

---

## Remediation

- **Use JavaScript-context-aware encoding:** Data reflected inside a JavaScript string must be JavaScript-string-escaped (escaping `'`, `"`, `\`, and other syntax-significant characters), not HTML-encoded. HTML encoding of `<`/`>` has no effect on this injection context.
- **Never build inline `<script>` content by string concatenation with user input:** Avoid embedding untrusted data directly into inline scripts. Prefer passing data to JavaScript via a safe channel — e.g., a `data-*` attribute read via `dataset`, or a JSON payload embedded in a `<script type="application/json">` block and parsed with `JSON.parse()`.
- **Content Security Policy (CSP):** A strict CSP disallowing inline scripts (`script-src 'self'` without `'unsafe-inline'`) would prevent this injected code from executing even if the string-breakout succeeded.
- **Match the encoding to the exact context:** This lab reinforces that the correct encoding scheme depends entirely on *where* the data lands — HTML body, HTML attribute, JavaScript string, or URL each require a different, purpose-built encoding function; applying the wrong one (or the right one to the wrong sink) leaves the application vulnerable.
