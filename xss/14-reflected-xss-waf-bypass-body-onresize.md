# Reflected XSS into HTML Context with Most Tags and Attributes Blocked (WAF Bypass)

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Practitioner
**Category:** Reflected XSS

---

## Problem

The lab's search functionality contains a reflected XSS vulnerability, but a Web Application Firewall (WAF) sits in front of it, blocking most common XSS vectors — standard payloads like `<img src=1 onerror=print()>` are rejected outright.

The goal is to bypass the WAF and perform a cross-site scripting attack that calls `print()`, **without any user interaction** (the exploit must fire automatically when delivered, not require a manual click in the tester's own browser).

---

## Discovery / Exploitation

1. Injected a standard payload, `<img src=1 onerror=print()>`, and confirmed it was blocked by the WAF.
2. Rather than guessing which tags/attributes were allowed, used **Burp Intruder** to systematically enumerate the WAF's allow-list:
   - Sent the search request to Intruder.
   - Set the search term to `<>` and placed a payload position between the angle brackets (`<§§>`).
   - Loaded PortSwigger's XSS cheat sheet list of HTML tags as the payload set and ran the attack.
   - Reviewed results by HTTP status code: most tag payloads returned `400` (blocked), but the `body` tag returned `200` — indicating `<body>` was not blocked by the WAF.
3. Repeated the same systematic approach for **event handler attributes**:
   - Set the search term to `<body%20=1>` with a payload position before the `=` (`<body%20§§=1>`).
   - Loaded the cheat sheet's list of event attributes as the payload set and ran the attack.
   - Most attribute payloads returned `400`, but `onresize` returned `200` — indicating `<body onresize=...>` was not blocked.
4. Combined the two surviving primitives (`<body>` tag + `onresize` event) into a working payload. Since `onresize` fires when an element's dimensions change, and the injected content sits inside an `<iframe>` on a delivered exploit page, the iframe's own resize (triggered via its `onload` handler) can be used to fire `onresize` on the embedded page automatically — satisfying the "no user interaction" requirement.

---

## Proof of Concept

**XSS payload (URL-encoded), delivered via the exploit server inside an iframe:**
```
"><body onresize=print()>
```

**Exploit server body:**
```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
```

**How it works:**
1. The iframe loads the target page with the WAF-surviving payload in the `search` parameter: `"><body onresize=print()>`.
2. `">` closes the existing HTML context the search term is reflected into, and `<body onresize=print()>` injects a new `<body>` element with an `onresize` handler.
3. The iframe's own `onload` handler changes the iframe's width (`this.style.width='100px'`), which forces the embedded page inside it to resize.
4. This resize event fires the injected `onresize` handler on the embedded page's `<body>` element, executing `print()` — with zero manual interaction from the victim.

**Steps to solve the lab:**
1. Use Burp Intruder as described above to identify `body` and `onresize` as WAF-permitted primitives.
2. Go to the exploit server and paste the iframe payload above (with the correct lab ID).
3. Click "Store", then "Deliver exploit to victim" to solve the lab.

---

## Remediation

- **Don't rely on WAF blocklists as the primary defense:** A WAF that blocks known-dangerous tags/attributes by name is fundamentally an incomplete blocklist — there will always be tags and event handlers it hasn't accounted for (as `<body>`/`onresize` demonstrate here). Contextual output encoding at the application layer remains the correct primary defense; a WAF should only be a supplementary layer.
- **Prefer allow-lists over blocklists where possible:** If tag/attribute filtering must be done, only permit a small, well-understood allow-list of safe tags and attributes, rather than trying to enumerate every dangerous one.
- **Content Security Policy (CSP):** A strict CSP disallowing inline event handlers would block payloads like `onresize=print()` from executing, even if the WAF's tag/attribute filter is bypassed.
- **Systematic fuzzing reveals WAF gaps quickly:** This lab illustrates how effective it is to fuzz a filter/WAF with a comprehensive payload list (like the PortSwigger XSS cheat sheet) rather than manually guessing — the same technique defenders should use to test their own WAF rules before relying on them.
