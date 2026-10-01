# Reflected XSS into a JavaScript String with Angle Brackets and Double Quotes HTML-Encoded and Single Quotes Escaped

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Practitioner
**Category:** Reflected XSS

---

## Problem

The lab's search query tracking functionality reflects user input inside a JavaScript string literal. Angle brackets (`<`, `>`) and double quotes (`"`) are HTML-encoded, and single quotes (`'`) are backslash-escaped — closing off both the HTML-tag-injection route and the direct single-quote string-breakout route used in earlier labs.

The goal is to perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

---

## Discovery / Exploitation

1. Submitted a random alphanumeric canary string and intercepted the request in Burp Suite, sending it to Burp Repeater.
2. Observed the canary string was reflected directly inside a JavaScript string literal.
3. Sent `test'payload` and confirmed the single quote was reflected as `\'` (backslash-escaped) — ruling out a direct quote-breakout.
4. Sent `test\payload` and confirmed the backslash itself was reflected **unescaped**, exactly as in the earlier JSON/`eval()` lab — the same escaping asymmetry (quotes escaped, backslash not) was present here too, just in a plain JavaScript string context rather than a JSON-via-`eval()` context.
5. Applied the same backslash-collision technique: sending a backslash immediately before the string-terminating character causes the server's own escaping logic to add a second backslash, producing a double backslash that resolves to one literal backslash — leaving the following quote free to actually terminate the string.

---

## Proof of Concept

**Payload used in the search box:**
```
\'-alert(1)//
```

**How the collision works:**

The server intends to escape any single quote in the input. Since the payload's own leading `\` is not escaped, the server's logic adds its own `\` in front of the `'` that follows:
```
\  +  \'  (server-added escape)  =  \\'
```
`\\` resolves to one literal backslash character; the `'` that follows it is therefore **not** treated as an escaped quote — it genuinely terminates the JavaScript string.

**Resulting injected script (illustrative):**
```javascript
var searchTerms = '\\'-alert(1)//';
```

**Breaking this down as JavaScript:**
- `\\` — one literal backslash, harmless
- `'` — closes the string early
- `-alert(1)` — the subtraction operator forces evaluation of `alert(1)` as part of a valid expression
- `//` — a JavaScript line comment, swallowing the remainder of the original line (including the trailing `';`) to avoid a syntax error

**Steps:**
1. Enter `\'-alert(1)//` into the search box (or set it as the `search` parameter directly).
2. Right-click the page, select "Copy URL", and paste the resulting URL into the browser.
3. On page load, the injected expression executes automatically and `alert(1)` fires — no user interaction required.

---

## Remediation

- **Escape backslashes before escaping the characters they could be used to collide with:** Server-side string-escaping logic must handle backslashes (`\` → `\\`) as a distinct, necessary step — escaping quotes alone, even correctly, is insufficient if the backslash used to perform that escaping is itself injectable and unescaped.
- **Avoid building inline `<script>` content via string concatenation with user input at all:** As with other JS-string-context labs, the most robust fix is architectural — pass untrusted data to JavaScript through a safe channel (e.g., a `data-*` attribute, or a `<script type="application/json">` block parsed with `JSON.parse()`) rather than trying to perfectly escape it inline.
- **Content Security Policy (CSP):** A strict CSP disallowing inline scripts would prevent this injected expression from executing even if the escaping bug remained.
- **Pattern recognition across labs:** This lab reinforces the lesson from the earlier JSON/`eval()` lab — "escape the quote, forget the backslash" is a recurring, easy-to-miss bug pattern across different serialization/output contexts (JSON strings, plain JS strings), so testing backslash-handling specifically is a high-value step whenever a quote-escaping defense is encountered.
