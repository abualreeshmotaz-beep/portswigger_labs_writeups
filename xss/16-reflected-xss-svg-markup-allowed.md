# Reflected XSS with Some SVG Markup Allowed

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Practitioner
**Category:** Reflected XSS

---

## Problem

The lab's search functionality reflects user input into the HTML body, protected by a filter that blocks common XSS tags — but the filter's blocklist misses certain SVG-specific tags and event attributes.

The goal is to perform a cross-site scripting attack that calls the `alert()` function.

---

## Discovery / Exploitation

1. Injected a standard payload, `<img src=1 onerror=alert(1)>`, and confirmed it was blocked by the filter.
2. Used **Burp Intruder** to systematically enumerate which tags the filter permits:
   - Sent the search request to Intruder, set the search term to `<>`, and placed a payload position between the angle brackets (`<§§>`).
   - Loaded PortSwigger's XSS cheat sheet list of tags as the payload set and ran the attack.
   - Reviewed results by HTTP status code: most tags returned `400` (blocked), but `svg`, `animatetransform`, `title`, and `image` all returned `200` — indicating these were not blocked.
3. Since `<animatetransform>` is a valid SVG-namespace element, it must be nested inside an `<svg>` element to be parsed and behave as intended (rather than being treated as an unrecognized generic element). Repeated the Intruder process for event attributes:
   - Set the search term to `<svg><animatetransform%20=1>` with a payload position before the `=` (`<svg><animatetransform%20§§=1>`).
   - Loaded the cheat sheet's list of event attributes as the payload set and ran the attack.
   - Most events returned `400`, but `onbegin` returned `200` — indicating this SVG-specific animation event was not blocked.
4. Combined the two surviving primitives (`<svg><animatetransform>` + `onbegin`) into a working payload. `onbegin` fires automatically as soon as the SVG animation element begins, requiring no click, focus, or other user interaction.

---

## Proof of Concept

**Payload used in the search box (URL-encoded form for direct browser use):**
```
"><svg><animatetransform onbegin=alert(1)>
```

**Resulting URL:**
```
https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Csvg%3E%3Canimatetransform%20onbegin=alert(1)%3E
```

**How it works:**
1. `">` closes the existing HTML attribute/context the search term is reflected into.
2. `<svg>` opens an SVG namespace context — a real, legitimate element the filter permits.
3. `<animatetransform onbegin=alert(1)>` is a valid SVG child element (normally used for animating shape transforms) carrying an `onbegin` event handler, also unblocked by the filter.
4. As soon as the browser parses and begins the (empty/no-op) animation element, the `onbegin` event fires automatically, executing `alert(1)` — with no user interaction required.

---

## Remediation

- **Don't rely on a tag/attribute blocklist, especially for SVG:** SVG defines a large namespace of specialized elements and events (`animate`, `animateTransform`, `animateMotion`, `set`, `onbegin`, `onend`, `onrepeat`, etc.) that are easy to overlook when building a blocklist, since they're far less well-known than standard HTML event handlers like `onclick` or `onload`.
- **Use a strict allow-list instead:** Only permit a small, well-understood set of safe tags with no event-handler or animation-trigger attributes at all.
- **Contextual output encoding remains the real fix:** HTML-encoding user input so `<` and `>` can never form any tag — SVG or otherwise — eliminates this entire vulnerability class regardless of which specific elements or events a filter has or hasn't accounted for.
- **Content Security Policy (CSP):** A strict CSP disallowing inline event handlers would prevent `onbegin=alert(1)` from executing even if the SVG tag/attribute filter gap remained.
- **Systematic fuzzing is the reliable way to find filter gaps:** As with the earlier WAF-bypass lab, exhaustively testing a filter against a comprehensive cheat-sheet payload list (via Burp Intruder) reveals gaps far faster and more reliably than manual guessing — a technique equally valuable for attackers and defenders auditing their own filters.
