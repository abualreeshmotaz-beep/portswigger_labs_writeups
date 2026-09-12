# Stored XSS into HTML Context with Nothing Encoded

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Apprentice
**Category:** Stored XSS

---

## Problem

The lab's blog comment functionality stores user-submitted comments and later renders them back to any visitor viewing the blog post, without any encoding or sanitization. Unlike reflected XSS, the payload doesn't need to be re-sent by the victim — once stored, it executes automatically for every user who views the affected page.

The goal is to submit a comment that triggers the `alert` function when the blog post is viewed.

---

## Discovery / Exploitation

1. Opened a blog post and located the "Leave a comment" form (Comment, Name, Email, Website fields).
2. Tested the comment field by submitting a canary value and viewing the page source after posting — confirmed the comment text is rendered directly into the HTML body of the page with no encoding of special characters.
3. Since the stored value is persisted server-side and reflected to every visitor (not just the submitter), this qualifies as a **stored/persistent XSS** — higher impact than reflected, since no social engineering of a single victim via a crafted link is needed.

---

## Proof of Concept

**Payload used in the Comment field:**
```html
<script>alert(1)</script>
```

**Steps:**
1. Fill in a Name, Email, and Website (required fields).
2. Enter the payload above into the Comment box.
3. Click "Post Comment".
4. Navigate back to the blog post page.
5. The stored comment is rendered into the page HTML, the injected `<script>` tag executes, and `alert(1)` fires — for anyone who views the post afterward.

---

## Remediation

- **Contextual output encoding:** HTML-encode all user-submitted content (comment, name, website, etc.) before rendering it back into the page — every time it's displayed, not just on initial submission.
- **Content Security Policy (CSP):** A strict CSP disallowing inline `<script>` execution significantly limits the impact even if a stored payload slips through.
- **Input validation/sanitization on write:** Reject or strip disallowed HTML tags/attributes from user-submitted fields at the point of storage, using an allow-list-based sanitizer rather than a blocklist.
- **Higher priority than reflected XSS:** Because stored XSS persists and auto-executes for every visitor, remediation here should be treated as higher severity/priority than an equivalent reflected XSS finding.
