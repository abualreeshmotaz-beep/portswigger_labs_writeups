# DOM XSS in jQuery Selector Sink Using a `hashchange` Event

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Apprentice
**Category:** DOM-based XSS

---

## Problem

The lab's home page contains a DOM-based XSS vulnerability triggered via a `hashchange` event. The client-side JavaScript listens for changes to `location.hash` and passes the value directly into jQuery's `$()` selector function to auto-scroll the page to a blog post matching that title.

**Source:** `location.hash`
**Sink:** jQuery `$()` selector function

Unlike the previous labs, this vulnerability requires delivering the exploit to a victim via the lab's built-in **exploit server**, since the trigger relies on the `hashchange` event firing after the initial page load (something a same-page self-attack via the address bar alone won't reliably reproduce). The goal is to deliver an exploit that calls the `print()` function in the victim's browser.

---

## Discovery / Exploitation

1. Inspected the home page's client-side JavaScript (via browser DevTools) and identified the vulnerable pattern:
   ```javascript
   $(window).on('hashchange', function() {
       var post = $('section.blog-list h2:contains(' + decodeURIComponent(location.hash.slice(1)) + ')');
       if (post) post.get(0).scrollIntoView();
   });
   ```
2. jQuery's `$()` function is polymorphic: if the string passed to it looks like an HTML tag (starts with `<`), jQuery creates and parses it as a DOM element instead of treating it purely as a CSS selector. Since `location.hash` is concatenated into this string unsanitized, injecting HTML markup causes jQuery to construct and insert real HTML elements into the DOM.
3. Because the sink only fires on the `hashchange` **event** (not on the initial page load with a hash already present), the exploit needs to load the target page first, then change the hash afterward — which is exactly what an `<iframe>` with an `onload` handler that appends to its own `src` accomplishes.

---

## Proof of Concept

**Exploit delivered via the PortSwigger exploit server, in the Body section:**
```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
```

**How it works, step by step:**
1. The `<iframe>` loads the target home page with an empty hash (`#`).
2. Once the iframe finishes loading, its `onload` handler fires and appends `<img src=x onerror=print()>` to the iframe's `src`, which changes `location.hash` on the embedded page.
3. This hash change fires the vulnerable `hashchange` event handler on the target page.
4. The malicious hash value (`<img src=x onerror=print()>`) is passed unsanitized into jQuery's `$()` selector, which parses it as real HTML and inserts an `<img>` element into the DOM.
5. The `src=x` is an invalid image path, triggering the `onerror` handler, which calls `print()`.

**Steps to solve the lab:**
1. Open the exploit server from the lab banner.
2. Paste the iframe payload above into the Body field.
3. Click "Store", then "View exploit" to confirm `print()` fires in the local preview.
4. Return to the exploit server and click "Deliver to victim" to solve the lab.

---

## Remediation

- **Avoid passing unsanitized strings into jQuery's `$()`:** Because `$()` behaves differently depending on whether its argument looks like a selector or an HTML string, never concatenate untrusted data directly into it. Use safer, purpose-specific methods instead (e.g., filter existing elements rather than building selectors dynamically from user input).
- **Validate/encode hash-derived values:** Treat `location.hash` as untrusted input, just like `location.search`. Strip or encode HTML-significant characters before using it to match content.
- **Content Security Policy (CSP):** A strict CSP disallowing inline event handlers (like `onerror=`) mitigates the practical impact even if the sink is reached.
- **Awareness of indirect/event-driven sinks:** This lab illustrates that DOM XSS isn't limited to values read once on page load — event listeners (`hashchange`, `popstate`, `message`, etc.) can reintroduce a source/sink pair at any point during the page's lifecycle, so client-side code should be audited for event handlers as thoroughly as for initial-load logic.
