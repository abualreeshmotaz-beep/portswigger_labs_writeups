# Reflected XSS into HTML Context with All Standard Tags Blocked

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Practitioner
**Category:** Reflected XSS

---

## Problem

The lab's search functionality reflects user input into the HTML body, protected by a filter that blocks all standard, known HTML tags (`<script>`, `<img>`, `<svg>`, `<body>`, etc.). However, the filter only recognizes and blocks tags from a known list of real HTML elements — it does not account for **custom (non-standard) tag names**, which browsers still parse as valid elements even though they carry no built-in meaning.

The goal is to perform a cross-site scripting attack that injects a custom tag and automatically calls `alert(document.cookie)`, with no manual user interaction.

---

## Discovery / Exploitation

1. Tested standard payloads (`<script>`, `<img onerror=...>`, `<svg onload=...>`, etc.) and confirmed all were blocked by the filter.
2. Recognized that HTML parsers accept **arbitrary, made-up tag names** as valid elements (e.g., `<xss>`), even though they have no predefined behavior — the browser still creates a DOM node for them and still applies any HTML attributes placed on them, including event handler attributes like `onfocus`.
3. Confirmed that a custom tag name was **not** blocked by the filter, since it doesn't match any entry in the filter's list of known dangerous tags.
4. Since a custom element still supports standard global HTML event attributes (`onfocus`, `onclick`, etc.), an event handler can be attached to it just like on any real element — `onfocus` was chosen because it can be triggered automatically without a click, using the `tabindex` attribute plus a URL fragment identifier to force focus on page load.

---

## Proof of Concept

**Delivered via the exploit server, using a redirect to force auto-focus on load:**
```html
<script>
location = 'https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';
</script>
```

**Decoded payload (the `search` parameter value):**
```html
<xss id=x onfocus=alert(document.cookie) tabindex=1>#x
```

**How it works, step by step:**
1. The custom tag `<xss>` is not a real HTML element and is not on the filter's blocklist, so it passes through unfiltered.
2. `tabindex=1` makes the otherwise non-interactive custom element focusable.
3. `onfocus=alert(document.cookie)` attaches an event handler that fires when the element receives focus.
4. `id=x` gives the element an ID matching the URL fragment `#x`.
5. The outer `<script>` on the exploit server navigates the victim's browser to the crafted URL. Because the URL includes the fragment `#x`, the browser automatically scrolls to and focuses the element with `id="x"` once the page loads — triggering `onfocus` with **no click or other manual interaction** required.
6. `alert(document.cookie)` fires automatically, demonstrating both XSS execution and the ability to exfiltrate session cookies in a real attack.

---

## Remediation

- **Never rely on a tag-name blocklist:** Blocking only known/standard tag names is fundamentally incomplete, since browsers accept and render arbitrary custom element names as valid HTML nodes with full support for global attributes and event handlers. A blocklist approach can never enumerate every possible tag name.
- **Use an allow-list for both tags and attributes:** Only permit a small, well-defined set of safe tags with no event-handler attributes at all, rather than trying to block dangerous ones by name.
- **Contextual output encoding remains the real fix:** HTML-encoding user input so that `<` and `>` can never form a tag in the first place (custom or otherwise) eliminates this entire vulnerability class, regardless of tag-naming tricks.
- **Content Security Policy (CSP):** A strict CSP disallowing inline event handlers (`onfocus=`, etc.) would prevent this specific payload from executing, even if the custom-tag filter bypass succeeded.
- **Auto-triggering technique reminder:** This lab also demonstrates that `tabindex` + a matching URL fragment (`#id`) can force focus (and thus fire `onfocus`) without any user interaction — a useful technique to recognize when auditing filters that assume click-based events require a real user action.
