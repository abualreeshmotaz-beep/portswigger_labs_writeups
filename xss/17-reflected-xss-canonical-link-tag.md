# Reflected XSS in Canonical Link Tag

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Practitioner
**Category:** Reflected XSS

---

## Problem

The lab reflects user input inside a `<link rel="canonical">` tag in the page's `<head>` — a location normally used only to tell search engines the preferred URL for the page, not intended to display or process user-facing content. Angle brackets (`<`, `>`) are escaped before being reflected, ruling out standard tag-injection techniques. However, the value is still reflected inside the tag's `href` attribute without adequate quote/attribute validation.

The goal is to perform a cross-site scripting attack on the home page that injects a new attribute and calls the `alert` function, given that the simulated victim will press one of a specific set of key combinations (`ALT+SHIFT+X` / `CTRL+ALT+X` / `Alt+X`, depending on OS). Note: the intended solution only works in Chrome.

---

## Discovery / Exploitation

1. Confirmed angle brackets were escaped in the reflected value, ruling out injecting a whole new HTML tag inside the `<head>`.
2. Since the reflection point is inside the canonical `<link>` tag's attribute area, the relevant technique is an **attribute breakout** (as in earlier attribute-context labs) rather than a tag-injection technique — closing the existing attribute and injecting new ones directly onto the same `<link>` element.
3. Recognized that a `<link>` element doesn't respond to typical mouse-based events like `onclick` unless it can somehow be "activated" — the key insight here is the `accesskey` HTML attribute, which lets *any* element (even a normally non-interactive one like `<link>`) be triggered via a keyboard shortcut, and pairing it with `onclick` fires the handler once that shortcut is pressed.
4. Since the lab states the simulated victim will press one of a known set of key combinations, the exploit doesn't need to force interaction automatically — it only needs to ensure that whichever shortcut the victim presses triggers the malicious attribute.

---

## Proof of Concept

**Payload — URL delivered to the victim:**
```
https://YOUR-LAB-ID.web-security-academy.net/?%27accesskey=%27x%27onclick=%27alert(1)
```

**Decoded form:**
```
?'accesskey='x'onclick='alert(1)
```

**Resulting injected markup (illustrative):**
```html
<link rel="canonical" href="https://YOUR-LAB-ID.web-security-academy.net/?'accesskey='x'onclick='alert(1)'>
```

**How it works, step by step:**
1. The leading `'` closes the existing `href='...'` attribute value early.
2. `accesskey='x'` is injected as a new attribute on the `<link>` element, binding the key `x` as a keyboard shortcut to activate this element.
3. `onclick='alert(1)'` is injected as another new attribute — the event handler that fires when the element is "activated" (which `accesskey` allows to happen via keyboard, not just a mouse click).
4. When the victim presses the platform-specific access-key combination (e.g., `Alt+Shift+X` on Windows Chrome), the browser treats it as if the element were clicked, firing `onclick` and executing `alert(1)`.

**Steps to solve the lab:**
1. Deliver (or visit, in Chrome) the crafted URL above.
2. Press the appropriate access-key combination for your OS (`ALT+SHIFT+X` on Windows, `CTRL+ALT+X` on macOS, `Alt+X` on Linux).
3. The `alert(1)` fires, solving the lab.

---

## Remediation

- **Treat every reflection point as attacker-controlled, including non-visual tags like `<link>`:** Even elements in `<head>` that aren't rendered visually can still carry executable attributes (`accesskey`, `onclick`, etc.) once injected, so they require the same rigorous output encoding as any body-context reflection.
- **HTML-attribute-encode quote characters, not just angle brackets:** Encoding `<`/`>` blocks new-tag injection but does nothing to prevent an attacker from closing and reopening attributes within an existing tag using unencoded quotes.
- **Content Security Policy (CSP):** A strict CSP disallowing inline event handlers (`onclick=`, etc.) would prevent this specific payload from executing even if the attribute-breakout succeeded.
- **Awareness of `accesskey` as an XSS enabler:** This lab highlights a lesser-known HTML feature — `accesskey` can make virtually any element "interactive" via a keyboard shortcut, extending the reach of otherwise inert-seeming injection points like `<link>`, `<meta>`, or other head-section tags.
