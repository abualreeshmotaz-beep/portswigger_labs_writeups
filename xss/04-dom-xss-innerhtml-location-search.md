# DOM XSS in `innerHTML` Sink Using Source `location.search`

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Apprentice
**Category:** DOM-based XSS

---

## Problem

The lab's search blog functionality contains a DOM-based XSS vulnerability. The client-side JavaScript reads user-controlled data from `location.search` (the URL query string) and assigns it directly to an element's `innerHTML` property, changing the HTML contents of a `div` without any sanitization.

**Source:** `location.search`
**Sink:** `innerHTML`

The goal is to perform a cross-site scripting attack that calls the `alert` function.

---

## Discovery / Exploitation

1. Entered a canary value into the search box and inspected the rendered page to confirm the value was being written into a `div`'s content.
2. Located the vulnerable client-side pattern:
   ```javascript
   function doSearchQuery(query) {
       document.getElementById('searchMessage').innerHTML = query;
   }
   var query = (new URLSearchParams(window.location.search)).get('search');
   if (query) {
       doSearchQuery(query);
   }
   ```
3. Unlike `document.write`, `innerHTML` parses and renders the assigned string as HTML directly into an existing element's content — there's no need to break out of an attribute, since the injection point isn't inside one. However, `<script>` tags inserted via `innerHTML` are **not executed** by the browser, so an event-handler-based payload is required instead.

---

## Proof of Concept

**Payload used in the search box:**
```html
<img src=1 onerror=alert(1)>
```

**Steps:**
1. Enter the payload above into the search box.
2. Click "Search".
3. The `<img>` tag is inserted directly into the `div`'s HTML via `innerHTML`.
4. The `src` attribute value (`1`) is not a valid image path, so the browser fails to load it and fires the `onerror` event handler.
5. The `onerror` handler executes `alert(1)`.

**Resulting URL:**
```
https://YOUR-LAB-ID.web-security-academy.net/?search=<img src=1 onerror=alert(1)>
```

---

## Remediation

- **Avoid `innerHTML` with untrusted data:** Never assign user-controlled input directly to `innerHTML`. Use `textContent` when only plain text needs to be displayed — it does not parse HTML at all.
- **Sanitize before rendering:** If HTML rendering is genuinely required, sanitize the input first using a well-tested library (e.g., DOMPurify) that strips dangerous tags/attributes while preserving safe markup.
- **Content Security Policy (CSP):** A strict CSP that disallows inline event handlers (like `onerror=`) prevents this specific payload from executing, adding a defense-in-depth layer.
- **Remember `innerHTML` blocks `<script>` but not event handlers:** Don't assume `innerHTML` is "safer" than `document.write` — attacker-controlled HTML via `innerHTML` can still execute JavaScript through event handler attributes (`onerror`, `onload`, etc.) or other HTML-based vectors (e.g., `<svg onload=...>`).
