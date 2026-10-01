# Reflected XSS into a Template Literal with Angle Brackets, Quotes, Backslash and Backticks Escaped

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Practitioner
**Category:** Reflected XSS

---

## Problem

The lab's search blog functionality reflects user input inside a JavaScript **template literal** (a string delimited by backticks `` ` `` rather than single or double quotes). Angle brackets (`<`, `>`) and quotes (`'`, `"`) are HTML-encoded, and backticks and backslashes are escaped — closing off every tag-injection, attribute-breakout, and string-escaping technique used in all previous labs.

The goal is to perform a cross-site scripting attack that calls the `alert` function inside the template string.

---

## Discovery / Exploitation

1. Submitted a random alphanumeric canary string, intercepted the request in Burp Suite, and sent it to Repeater.
2. Observed the canary string was reflected inside a JavaScript **template literal** (backtick-delimited string), e.g.:
   ```javascript
   var message = `Search results for CANARY_VALUE`;
   ```
3. Confirmed angle brackets, both quote types, backticks, and backslashes were all properly encoded/escaped in the response — every character-level escape technique used in prior labs (breaking out with `'`, `"`, `` ` ``, or colliding via `\`) was closed off.
4. Recognized that template literals have a unique feature with no equivalent in regular single/double-quoted strings: **expression interpolation** via `${ }`. Any valid JavaScript expression placed inside `${ }` is evaluated live and its result is substituted into the string — critically, this syntax relies entirely on the `$`, `{`, and `}` characters, none of which were being encoded or escaped by the application's filter.

---

## Proof of Concept

**Payload used in the search box:**
```
${alert(1)}
```

**Resulting injected script:**
```javascript
var message = `Search results for ${alert(1)}`;
```

**How it works:**
1. The JavaScript engine evaluates the template literal and encounters the `${ }` interpolation syntax.
2. It evaluates the expression inside — `alert(1)` — as live JavaScript, exactly as template literals are designed to do for legitimate variable interpolation.
3. `alert(1)` fires as a side effect of this evaluation; its return value (`undefined`) is then substituted into the resulting string, but by that point the alert has already executed.
4. No angle brackets, quotes, backticks, or backslashes were needed anywhere in the payload, so none of the application's escaping defenses had any effect on this attack.

**Steps:**
1. Enter `${alert(1)}` into the search box.
2. Right-click the page, select "Copy URL", and paste the resulting URL into the browser.
3. On page load, the injected expression executes automatically, and `alert(1)` fires — no user interaction required.

---

## Remediation

- **Encode/escape the `$`, `{`, and `}` characters when reflecting data into a template literal context:** These are the syntax-significant characters for this specific context (expression interpolation), just as `'` and `\` are for regular string literals. A defense that only accounts for quote/backtick/backslash escaping — the "usual suspects" from other string contexts — misses the characters that actually matter for template literals.
- **Avoid reflecting untrusted data inside any inline `<script>` content, template literal or otherwise:** The most robust fix remains architectural — pass data to JavaScript via a safe channel outside the script body (e.g., a `data-*` attribute or a `<script type="application/json">` block parsed with `JSON.parse()`), rather than trying to enumerate and escape every syntax-significant character for every possible JavaScript string type.
- **Content Security Policy (CSP):** A strict CSP disallowing inline scripts would prevent this injected expression from executing even if the `${ }` interpolation bypass succeeded.
- **Context-specific character sets, not a one-size-fits-all escape list:** This lab is the clearest demonstration yet that "the dangerous characters" differ by context — HTML body needs `<`/`>` encoded, HTML attributes need quotes encoded, regular JS strings need `'`/`"`/`\` escaped, and template literals additionally need `` ` ``, `$`, `{`, and `}` handled. A checklist built for one context is not automatically safe for another.
