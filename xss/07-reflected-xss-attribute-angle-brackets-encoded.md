# Reflected XSS into Attribute with Angle Brackets HTML-Encoded

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Apprentice
**Category:** Reflected XSS

---

## Problem

The lab's search blog functionality reflects user input back inside a quoted HTML attribute. Unlike the first reflected XSS lab, this application does apply some encoding — angle brackets (`<` and `>`) are HTML-encoded before being reflected, which prevents injecting a new tag such as `<script>`. However, the double-quote character (`"`) used to delimit the attribute is **not** encoded, so the attribute itself can still be broken out of.

The goal is to perform a cross-site scripting attack that injects a new attribute and calls the `alert` function.

---

## Discovery / Exploitation

1. Submitted a random alphanumeric canary string into the search box.
2. Intercepted the search request in Burp Suite and sent it to Burp Repeater for faster iteration.
3. Observed that the canary string was reflected inside a quoted HTML attribute (e.g., a `value="..."` attribute on the search `<input>` element).
4. Tested injecting angle brackets (`<`, `>`) and confirmed they were HTML-encoded (`&lt;`, `&gt;`) in the response — ruling out the "inject a whole new tag" approach used in earlier labs.
5. Tested injecting a double-quote character (`"`) and confirmed it was reflected **unencoded** — meaning the existing attribute could be closed early, and a new attribute could be injected onto the same element without needing to open a new tag at all.

---

## Proof of Concept

**Payload used in the search box:**
```
"onmouseover="alert(1)
```

**Resulting injected markup (illustrative):**
```html
<input type="text" placeholder="Search the blog..." name="search" value="" onmouseover="alert(1)" "="">
```

**Steps:**
1. Enter the payload above into the search box (or modify the `search` parameter directly in Burp Repeater).
2. The closing `"` ends the original `value="..."` attribute.
3. `onmouseover="alert(1)"` is injected as a brand-new attribute on the same `<input>` element.
4. The trailing `"` from the payload combines with the encoded `>` that follows in the markup, closing out harmlessly without breaking the tag.
5. Right-click the page, select "Copy URL" (with the payload in the `search` query parameter), and open that URL directly in the browser.
6. Move the mouse over the injected input element — the `onmouseover` event fires, triggering `alert(1)`.

**Resulting URL:**
```
https://YOUR-LAB-ID.web-security-academy.net/?search="onmouseover="alert(1)
```

---

## Remediation

- **Encode all attribute-breaking characters, not just angle brackets:** Attribute-context output encoding must escape double quotes (`"`), single quotes (`'`), and other characters that can terminate the attribute value — encoding only `<`/`>` is insufficient when the injection point is inside an attribute rather than the HTML body.
- **Use context-aware encoding libraries:** Rely on a well-tested auto-escaping template engine or encoding library that applies the correct encoding rules for the specific context (HTML body vs. HTML attribute vs. JavaScript string vs. URL), rather than a single blanket encoding function.
- **Content Security Policy (CSP):** A strict CSP that disallows inline event handlers (`onmouseover=`, `onload=`, etc.) would prevent this specific payload from executing even if the attribute breakout succeeded.
- **Lesson on partial encoding:** This lab demonstrates that partial/incomplete encoding (encoding some dangerous characters but not others) still leaves the application vulnerable — a security control must cover every character relevant to the injection context, not just the most obvious ones (`<`, `>`).
