# DOM XSS in `document.write` Sink Using Source `location.search` Inside a `select` Element

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Practitioner
**Category:** DOM-based XSS

---

## Problem

The lab's stock checker functionality contains a DOM-based XSS vulnerability. The client-side JavaScript reads a value from `location.search` and writes it into the page via `document.write()`, where it is enclosed inside a `<select>`/`<option>` element used to build a store-selection dropdown.

**Source:** `location.search` (parameter `storeId`)
**Sink:** `document.write()`

The vulnerable pattern:
```javascript
var stores = ["London","Paris","Milan"];
var store = (new URLSearchParams(window.location.search)).get('storeId');
document.write('<select name="storeId">');
if (store) {
    document.write('<option selected>'+store+'</option>');
}
for (var i=0; i<stores.length; i++) {
    if (stores[i] === store) {
        continue;
    }
    document.write('<option>'+stores[i]+'</option>');
}
document.write('</select>');
```

The goal is to perform a cross-site scripting attack that breaks out of the `<select>` element and calls the `alert` function.

---

## Discovery / Exploitation

1. Read the client-side JavaScript directly (via View Source / DevTools) to identify the parameter name and sink, rather than guessing: `.get('storeId')` confirmed the query parameter is `storeId`, and `document.write` confirmed the sink.
2. Sent a probing value with a leading double-quote (`?storeId="z3nsh3ll`) and inspected the rendered DOM. The value landed as **text content** between `<option selected>` and `</option>` — not inside an HTML attribute — confirming this is a body/text injection context, not an attribute-breakout scenario like earlier `document.write` labs.
3. Since the value is enclosed inside an existing `<select>` element (opened before the injection point and closed after it in the original code), the injection needs to explicitly close the `</select>` tag early before any new tag (like `<img>`) will be parsed correctly as a sibling element rather than being nested inside the dropdown.

---

## Proof of Concept

**Payload — set the `storeId` parameter to:**
```
"z3nsh3ll</select><img src="1" onerror="alert()">
```

**Resulting injected markup:**
```html
<select name="storeId">
<option selected>"z3nsh3ll</select><img src="1" onerror="alert()"></option>
```

**Steps:**
1. Navigate to the product page with the payload in the `storeId` parameter:
   ```
   https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&storeId="z3nsh3ll</select><img src="1" onerror="alert()">
   ```
2. The `</select>` closes the dropdown element early, ending the constrained context.
3. The subsequent `<img src="1" onerror="alert()">` is parsed as a new, independent element outside the `<select>`.
4. `src="1"` is an invalid image path, so the browser fails to load it and fires the `onerror` handler, executing `alert()`.

---

## Remediation

- **Contextual output encoding:** HTML-encode user-controlled data before writing it into the page body (`<`, `>`, `"`, `'`), regardless of which specific tag it's nested inside. Body-context encoding would have prevented `</select>` and `<img ...>` from being parsed as real markup.
- **Avoid `document.write` with untrusted data:** As with earlier labs, prefer safer DOM construction methods (e.g., creating elements via `document.createElement` and setting `textContent`) over building raw HTML strings with `document.write`.
- **Validate against an allow-list:** Since the valid store values are a known, fixed set (`London`, `Paris`, `Milan`), the application should validate `storeId` against that allow-list server- or client-side and reject/ignore any value that doesn't match, rather than reflecting arbitrary input into the page at all.
- **Lesson on nested-element contexts:** This lab builds on the original `document.write` lab by showing that the required "breakout" sequence depends on the surrounding tag structure — here, closing a parent element (`</select>`) is a necessary first step before a new element can render as intended, not just closing an attribute.
