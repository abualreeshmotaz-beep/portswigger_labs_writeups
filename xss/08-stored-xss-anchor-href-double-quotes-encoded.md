# Stored XSS into Anchor `href` Attribute with Double Quotes HTML-Encoded

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Apprentice
**Category:** Stored XSS

---

## Problem

The lab's comment functionality contains a stored XSS vulnerability in the "Website" field. The submitted website URL is stored and later used as the `href` attribute of an anchor (`<a>`) element wrapping the comment author's name. Double quotes are HTML-encoded before being reflected, which prevents breaking out of the `href="..."` attribute directly — but the value inside the attribute itself is not validated as a safe URL scheme.

The goal is to submit a comment that calls the `alert` function when the comment author name is clicked.

---

## Discovery / Exploitation

1. Posted a comment with a random alphanumeric canary string in the "Website" field.
2. Intercepted the comment submission request in Burp Suite and sent it to Burp Repeater.
3. Made a second request in the browser to view the blog post (loading the stored comment), intercepted that request too, and sent it to a second Repeater tab.
4. In the response, observed the canary string reflected inside an anchor's `href` attribute wrapping the comment author's name:
   ```html
   <a href="CANARY_VALUE">Author Name</a>
   ```
5. Tested injecting a double quote (`"`) in the Website field and confirmed it was HTML-encoded (`&quot;`) in the response — ruling out breaking out of the attribute the way earlier labs did.
6. Since the entire, unbroken `href` value is attacker-controlled, the attribute-breakout technique isn't needed at all — the value can instead be replaced wholesale with a `javascript:` URI, which requires no quote characters to work.

---

## Proof of Concept

**Payload — submitted in the "Website" field when posting the comment:**
```
javascript:alert(1)
```

**Resulting stored markup:**
```html
<a href="javascript:alert(1)">Author Name</a>
```

**Steps:**
1. Post a comment, entering `javascript:alert(1)` in the Website field (along with required Name/Email/Comment).
2. Navigate to (or refresh) the blog post page where the comment is displayed.
3. Right-click the page, select "Copy URL", and paste the URL into the browser to load the page fresh.
4. Click the comment author's name (now rendered as a link with the malicious `href`).
5. Since the `href` begins with `javascript:`, the browser executes the script instead of navigating, triggering `alert(1)`.

---

## Remediation

- **Validate URL schemes before storing/rendering:** Restrict the "Website" field to an allow-list of safe schemes (`http:`, `https:`) and reject anything else, including `javascript:`, `data:`, and `vbscript:`.
- **Don't rely on quote-encoding alone:** Encoding double quotes prevents attribute-breakout attacks, but it does nothing to stop a malicious value from being accepted wholesale as the attribute's content — output encoding and input/scheme validation address different threats and are both required.
- **Content Security Policy (CSP):** While not all browsers block `javascript:` URIs via CSP by default, a strict CSP combined with scheme validation adds defense-in-depth.
- **Stored XSS severity reminder:** Because this payload is persisted and served to every visitor who views the post and clicks the link, it should be prioritized as high-severity — it requires only one click from any victim, not a crafted link sent by the attacker each time.
