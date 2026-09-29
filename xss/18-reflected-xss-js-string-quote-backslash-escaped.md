# Reflected XSS into a JavaScript String with Single Quote and Backslash Escaped

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Practitioner
**Category:** Reflected XSS

---

## Problem

The lab's search query tracking functionality reflects user input inside a JavaScript string literal within an inline `<script>` block:
```javascript
var searchTerms = 'z3nsh3l';
document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
```

Unlike the earlier JS-string-context lab, here **both** the single quote (`'`) and the backslash (`\`) are properly HTML/JS-escaped before being reflected — closing off the string-breakout and backslash-collision techniques used previously. The goal is to perform a cross-site scripting attack that calls the `alert` function despite this.

---

## Discovery / Exploitation

1. Sent a probing value containing a single quote (`'`) and confirmed it was reflected as `\'` — properly escaped.
2. Sent a probing value containing a backslash (`\`) and confirmed it was reflected as `\\` — also properly escaped.
3. Attempted the backslash-collision technique from an earlier lab (sending `\'+alert()`) and confirmed it did **not** work: both characters were escaped correctly, so the injected value remained safely trapped as inert text inside the string, and `alert()` was never evaluated as code.
4. Recognized that since both quote-breakout and backslash-collision were closed off, the injection point still lands inside an HTML page parsed by the browser **before** the JavaScript is executed. Rather than trying to break out of the JavaScript string itself, the `<script>` tag containing it can be closed directly at the HTML level — the browser's HTML parser looks for a literal `</script>` sequence to end a script block, regardless of whether the JavaScript inside is syntactically complete or is even aware that a quote/backslash-escaping scheme exists.

---

## Proof of Concept

**Payload used as the search term:**
```html
</script><script>alert()</script>
```

**Resulting markup as parsed by the browser:**
```html
<script>
    var searchTerms = '</script><script>alert()</script>';
    document.write(...);
</script>
```

**How it works, step by step:**
1. The browser's HTML parser scans the page and, upon encountering `</script>` (regardless of it appearing inside a JavaScript string literal, as far as the HTML parser is concerned it's just a closing tag token), closes the original `<script>` block immediately — even though the JavaScript inside it (`var searchTerms = '...`) was left syntactically incomplete.
2. `<script>alert()</script>` opens a brand-new, independent script block, which the browser parses and executes normally.
3. `alert()` fires — no string-breakout or backslash trick against the JS-escaping logic was needed at all, because the attack operates one layer up, at the HTML-parsing level rather than the JavaScript-syntax level.

---

## Remediation

- **HTML-encode data before embedding it in any inline `<script>` block:** Escaping only JavaScript-syntax characters (`'`, `\`) is insufficient. The literal sequence `</script>` must also be neutralized (e.g., by encoding `<` as `\u003C` or splitting the sequence) before being placed inside a script block, since the HTML parser processes tag boundaries independent of JavaScript string escaping.
- **Never build inline `<script>` content by string concatenation with user input:** As emphasized in the earlier JS-string-context lab, prefer passing untrusted data to JavaScript via a safe channel entirely outside the script body — e.g., a `data-*` attribute read via `dataset`, or a JSON payload in a `<script type="application/json">` block parsed with `JSON.parse()`.
- **Content Security Policy (CSP):** A strict CSP disallowing inline scripts (`script-src 'self'` without `'unsafe-inline'`) would prevent the injected second `<script>` block from executing even if this HTML-parser-level bypass succeeded.
- **Key lesson — two separate parsing layers:** This lab demonstrates that JavaScript-string escaping and HTML-tag parsing are two entirely separate defenses operating at different layers. Perfectly escaping a value for the JavaScript-string context does not protect against an attacker closing the surrounding HTML `<script>` element itself — both layers must be defended independently.
