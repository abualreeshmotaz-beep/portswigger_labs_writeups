# Reflected DOM XSS (JSON Response Processed with `eval()`)

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Practitioner
**Category:** DOM-based XSS (Reflected DOM)

---

## Problem

This lab demonstrates a **reflected DOM vulnerability**: the server-side application processes data from a request and echoes it back in the response — here, as a JSON payload — and a client-side script then processes that JSON in an unsafe way, ultimately passing it to a dangerous sink (`eval()`).

**Source:** the `search` request parameter, echoed back inside a JSON response
**Sink:** `eval()`, called on the raw JSON response text in `searchResults.js`

The goal is to create an injection that calls the `alert()` function.

---

## Discovery / Exploitation

1. Enabled Burp Suite's Proxy Intercept feature.
2. Submitted a test search string (e.g. `"XSS"`) through the search bar and forwarded the intercepted request.
3. Observed that the search term was reflected inside a JSON response named `search-results`.
4. Opened `searchResults.js` from the Site Map and found that this JSON response is passed directly into an `eval()` call rather than a safe parser like `JSON.parse()` — meaning the response text is executed as live JavaScript, not just parsed as inert data.
5. Experimented with different characters in the search term and found that double-quote characters (`"`) in the reflected value were being escaped (prefixed with a backslash) before being embedded in the JSON response — but the backslash character (`\`) itself was **not** being escaped.
6. This asymmetry (quotes escaped, backslashes not) meant a backslash sent by the attacker could be used to "consume" the server's own escaping backslash, causing the pair to cancel out and leaving the following double-quote unescaped — able to terminate the string early.

---

## Proof of Concept

**Payload used as the search term:**
```
\"-alert(1)}//
```

**How the payload transforms the response:**

The server intends to build a response like:
```json
{"searchTerm":"<escaped search term>", "results":[]}
```

Given the injected backslash is not escaped, the server's own quote-escaping logic adds a second backslash in front of the injected `"`, producing a double backslash — which JavaScript interprets as one literal, "consumed" backslash, leaving the quote that follows unescaped:

```json
{"searchTerm":"\\"-alert(1)}//", "results":[]}
```

**Breaking this down as it's parsed by `eval()`:**
- `\\` — a single literal (escaped) backslash character, harmless
- `"` — now unescaped, so it closes the `searchTerm` string early
- `-alert(1)` — the subtraction operator separates this from the (now-closed) string expression and forces `alert(1)` to be evaluated
- `}` — closes the JSON object early
- `//` — a JavaScript line comment, which swallows the remainder of the original object structure so the overall statement remains syntactically valid and doesn't throw an error

**Steps:**
1. Enter `\"-alert(1)}//` into the search box (or set it as the `search` parameter directly).
2. The vulnerable client-side script calls `eval()` on the resulting JSON-shaped response.
3. Because the response is executed as JavaScript rather than parsed as data, the injected `alert(1)` runs, and `}//` closes/comments out the remainder cleanly to avoid a syntax error.

---

## Remediation

- **Never use `eval()` to process JSON responses:** Replace `eval(jsonString)` with `JSON.parse(jsonString)`. `JSON.parse` strictly validates JSON syntax and throws an error on anything that isn't well-formed data — it cannot execute injected JavaScript expressions, eliminating this vulnerability class entirely.
- **Escape all syntax-significant characters, not just quotes:** Server-side JSON serialization must escape backslashes (`\` → `\\`) in addition to double quotes; escaping only one of the two characters that give the other its meaning leaves an exploitable asymmetry, as demonstrated here.
- **Use a proper JSON serialization library:** Rely on a well-tested, standard JSON-encoding library/function on the server side rather than manual string concatenation or partial escaping logic, which is easy to get subtly wrong (as seen in this lab).
- **Content Security Policy (CSP):** While CSP does not prevent `eval()` from running unless explicitly configured to block it (`script-src` without `'unsafe-eval'`), enforcing such a policy would have blocked this exploit even if the escaping bug remained.
