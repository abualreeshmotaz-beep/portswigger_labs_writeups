# Stored XSS into `onclick` Event with Angle Brackets and Double Quotes HTML-Encoded and Single Quotes and Backslash Escaped

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Practitioner
**Category:** Stored XSS

---

## Problem

The lab's comment functionality stores the submitted "Website" value and later reflects it inside an `onclick` event handler attribute on the comment author's name. Angle brackets (`<`, `>`) and double quotes (`"`) are HTML-encoded, and both single quotes (`'`) and backslashes (`\`) are properly escaped — closing off every technique used in earlier attribute-breakout and backslash-collision labs.

The goal is to submit a comment that calls the `alert` function when the comment author name is clicked.

---

## Discovery / Exploitation

1. Posted a comment with a random alphanumeric canary string in the "Website" field, intercepted the submission in Burp Suite, and sent it to Repeater.
2. Loaded the blog post page to view the stored comment, intercepted that request too, and sent it to a second Repeater tab.
3. Observed the canary string reflected inside an `onclick` attribute on the author name link, e.g.:
   ```html
   <a href="#" onclick="var tracker={track:function(){}};tracker.track('CANARY_VALUE');">Author Name</a>
   ```
4. Tested single quotes and backslashes individually and confirmed **both** were properly escaped this time (`'` → `\'`, `\` → `\\`) — ruling out both the direct quote-breakout technique and the backslash-collision technique used in previous labs.
5. Since character-level escaping (quotes, backslashes, angle brackets) was fully closed off, pivoted to a different encoding layer entirely: **HTML entities**. The server/client-side escaping logic inspects the literal characters in the submitted value, but the browser's HTML parser decodes HTML entities (like `&apos;` for `'`) *before* handing the resulting text to the JavaScript engine — meaning a quote smuggled in as `&apos;` passes straight through the escaping filter (since it isn't a literal `'` character at the time the filter inspects it) and only becomes a real `'` after the browser renders the HTML, at which point it's too late for any JS-string-escaping defense to catch it.

---

## Proof of Concept

**Payload used in the "Website" field:**
```
http://foo?&apos;-alert(1)-&apos;
```

**Resulting stored/rendered markup (illustrative):**
```html
<a href="#" onclick="var tracker={track:function(){}};tracker.track('http://foo?'-alert(1)-'');">Author Name</a>
```

**How it works, step by step:**
1. The value is submitted containing the HTML entity `&apos;` instead of a literal `'` character.
2. The server-side escaping logic scans the submitted value for literal `'` and `\` characters to escape — but `&apos;` doesn't contain either, so it passes through completely unmodified.
3. The value is stored and later embedded in the `onclick` attribute, still as the literal text `&apos;`.
4. When the browser parses the page's HTML to render it, it decodes `&apos;` into an actual `'` character **as part of normal HTML attribute parsing** — this happens *before* the browser hands the attribute's content to the JavaScript engine to execute on click.
5. By the time the JavaScript engine evaluates the `onclick` handler, the `'` characters are real, genuinely terminating the string early and allowing `-alert(1)-` to be evaluated as a JavaScript expression.

**Steps to solve the lab:**
1. Post a comment with `http://foo?&apos;-alert(1)-&apos;` in the Website field.
2. Navigate to the blog post page.
3. Right-click the page, select "Copy URL", and paste it into the browser to load the page fresh.
4. Click the comment author's name — the `onclick` handler fires, and `alert(1)` executes.

---

## Remediation

- **Decode HTML entities before applying JavaScript-string escaping, or escape after the browser's decoding point:** Server-side filtering that inspects raw submitted characters is bypassed if the dangerous character is submitted in HTML-entity form instead, since the browser decodes entities during HTML parsing — a step the escaping filter doesn't account for.
- **Never build inline event-handler attributes from user input at all:** The most robust fix is architectural — attach event listeners via `addEventListener()` in a separate script, passing data through safe mechanisms (e.g., `dataset` attributes), rather than concatenating untrusted data directly into an `onclick="..."` string.
- **Content Security Policy (CSP):** A strict CSP disallowing inline event handlers would prevent this payload from executing even if the HTML-entity bypass succeeded.
- **Defense-in-depth across encoding layers:** This lab demonstrates that escaping must account for every representation of a dangerous character — literal, HTML-entity-encoded, and any other equivalent form the browser will eventually decode — not just the character's single literal form.
