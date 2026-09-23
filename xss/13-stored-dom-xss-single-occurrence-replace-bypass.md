# Stored DOM XSS — Bypassing Single-Occurrence `replace()` Angle Bracket Encoding

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Practitioner
**Category:** DOM-based XSS (Stored DOM)

---

## Problem

This lab demonstrates a stored DOM vulnerability in the blog comment functionality. The application attempts to defend against XSS by encoding angle brackets in submitted comments using JavaScript's `replace()` function — but calls it with a plain string as the first argument rather than a global regular expression.

The goal is to exploit this vulnerability to call the `alert()` function.

---

## Discovery / Exploitation

1. Tested submitting a comment containing multiple angle brackets and observed that only the **first** `<` and the **first** `>` in the comment were encoded to `&lt;`/`&gt;` — any subsequent angle brackets were reflected completely unencoded.
2. This behavior is characteristic of JavaScript's `String.prototype.replace()` when called with a string (not a regex with the `/g` global flag) as the search argument:
   ```javascript
   comment.replace("<", "&lt;").replace(">", "&gt;")
   ```
   `.replace("<", "&lt;")` only replaces the **first occurrence** of `<` in the string, leaving every other `<` untouched. The same applies to `.replace(">", "&gt;")` and `>`.
3. This means the filter can be exhausted by supplying a throwaway pair of angle brackets at the very start of the comment — consuming the single replacement — after which any real HTML tags injected later in the same comment pass through completely unencoded.

---

## Proof of Concept

**Payload used in the comment field:**
```html
<><img src=1 onerror=alert(1)>
```

**How the filter is bypassed, step by step:**

| Payload segment | What happens to it |
|---|---|
| `<` (1st) | Consumed by the filter's single `<` → `&lt;` replacement |
| `>` (1st) | Consumed by the filter's single `>` → `&gt;` replacement |
| `<img src=1 onerror=alert(1)>` | The filter has already used its one-time replacement for each character — these angle brackets pass through **unencoded** |

**Resulting stored/rendered markup:**
```html
&lt;&gt;<img src=1 onerror=alert(1)>
```

**Steps:**
1. Post a comment with the payload `<><img src=1 onerror=alert(1)>` (along with any other required fields).
2. Navigate to (or reload) the blog post page displaying the comment.
3. The dummy `<>` pair renders harmlessly as encoded text, but the real `<img src=1 onerror=alert(1)>` tag is inserted into the DOM as live HTML.
4. `src=1` is an invalid image path, triggering the `onerror` handler, which executes `alert(1)`.

---

## Remediation

- **Use a global regular expression, not a plain string, with `replace()`:** To encode *every* occurrence of a character, the search argument must be a regex with the `g` flag: `comment.replace(/</g, "&lt;").replace(/>/g, "&gt;")`. A plain string argument only ever replaces the first match.
- **Prefer a dedicated HTML-encoding function or library:** Rather than hand-rolling character replacement logic (which is easy to get subtly wrong, as this lab demonstrates), use a well-tested, purpose-built encoding function that guarantees complete and correct escaping for the target context.
- **Content Security Policy (CSP):** A strict CSP disallowing inline event handlers (`onerror=`, etc.) would mitigate the practical impact even if a filter bypass like this one is found.
- **Test filters against multiple/repeated payloads, not just single characters:** This lab is a reminder that a filter which appears to work against a simple single-tag test case can still be fundamentally broken — always test with multiple instances of the "dangerous" character to confirm a filter is applied globally, not just once.
