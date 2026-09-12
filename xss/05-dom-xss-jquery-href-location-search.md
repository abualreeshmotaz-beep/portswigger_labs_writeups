# DOM XSS in jQuery Anchor `href` Attribute Sink Using Source `location.search`

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Apprentice
**Category:** DOM-based XSS

---

## Problem

The lab's "Submit feedback" page contains a DOM-based XSS vulnerability. The client-side JavaScript uses jQuery's `$` selector to locate an anchor (`<a>`) element — the "back" link — and sets its `href` attribute using a value taken directly from `location.search`, without validating that the value is a safe, expected URL.

**Source:** `location.search`
**Sink:** jQuery `.attr('href', ...)`

The goal is to make the "back" link execute `alert(document.cookie)` when clicked.

---

## Discovery / Exploitation

1. On the Submit feedback page, changed the `returnPath` query parameter to `/` followed by a random alphanumeric string.
2. Right-clicked the "back" link and chose "Inspect" — confirmed the random string had been placed directly inside the anchor's `href` attribute, matching a pattern like:
   ```javascript
   $(function() {
       $('#backLink').attr('href', function() {
           return location.search.match(/returnPath=(.*)/)[1];
       });
   });
   ```
3. Since the raw value of `returnPath` is used as the entire `href` value (not concatenated inside a larger string), there's no need to "break out" of anything — the attribute value itself can be fully replaced with a `javascript:` URI, which the browser will execute instead of navigating when the link is clicked.

---

## Proof of Concept

**Payload — set the `returnPath` parameter to:**
```
javascript:alert(document.cookie)
```

**Resulting URL:**
```
https://YOUR-LAB-ID.web-security-academy.net/feedback?returnPath=javascript:alert(document.cookie)
```

**Steps:**
1. Navigate to the URL above (or edit the `returnPath` parameter in the address bar and press Enter).
2. Click the "back" link on the page.
3. Since the `href` is now `javascript:alert(document.cookie)`, the browser executes the script instead of navigating, popping an alert containing the current page's `document.cookie`.

**Note:** Unlike the `document.write` and `innerHTML` labs, this vulnerability requires **user interaction** (a click on the link) to trigger — it does not fire automatically on page load.

---

## Remediation

- **Validate URLs before use:** Before assigning user-controlled data to an `href` attribute, validate that the value is a relative path or matches an allow-list of expected URL schemes (e.g., `http:`, `https:`, `/`), explicitly rejecting `javascript:` and other dangerous schemes (`data:`, `vbscript:`).
- **Avoid raw parameter values in sinks:** Don't pass unvalidated `location.search`/`location.hash` data straight into DOM sinks that affect navigation or code execution (`href`, `src`, `action`).
- **Content Security Policy (CSP):** While CSP does not block `javascript:` URIs by default in all browsers, combining CSP with strict input validation provides stronger defense-in-depth.
- **Demonstrates real-world impact:** This payload (`alert(document.cookie)`) illustrates session hijacking risk — in a real attack, the stolen cookie would be exfiltrated to an attacker-controlled server instead of just being displayed in an alert.
