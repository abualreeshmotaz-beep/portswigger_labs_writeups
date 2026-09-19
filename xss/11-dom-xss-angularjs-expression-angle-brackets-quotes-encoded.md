# DOM XSS in AngularJS Expression with Angle Brackets and Double Quotes HTML-Encoded

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Practitioner
**Category:** DOM-based XSS

---

## Problem

The lab's search functionality contains a DOM-based XSS vulnerability inside an AngularJS expression. The page includes an HTML node with the `ng-app` directive, which causes AngularJS to scan that node's contents and evaluate any expression written inside double curly braces (`{{ ... }}`) as live JavaScript.

Both angle brackets (`<`, `>`) and double quotes (`"`) are HTML-encoded before the search term is reflected — normally this would block HTML tag injection and attribute breakout entirely. However, since the reflection point is inside an `ng-app`-scoped node, none of that matters: an AngularJS expression requires neither angle brackets nor quotes to execute.

The goal is to perform a cross-site scripting attack that executes an AngularJS expression and calls the `alert` function.

---

## Discovery / Exploitation

1. Entered a random alphanumeric canary string into the search box.
2. Viewed the page source and observed that the reflected search term was enclosed inside an element carrying the `ng-app` directive — meaning AngularJS was actively loaded and scanning that section of the page.
3. Confirmed angle brackets and double quotes were both HTML-encoded in the response, ruling out standard tag-injection and attribute-breakout techniques used in earlier labs.
4. Since AngularJS evaluates `{{ }}` expressions as JavaScript regardless of HTML encoding (the encoding only affects HTML parsing, not AngularJS's own expression evaluator), tested a basic arithmetic expression (`{{ 1 + 1 }}`) and confirmed it was evaluated server-side-rendered-looking output showed `2` instead of the literal string — proving live expression evaluation was occurring.
5. Attempted `{{alert()}}` directly, which was blocked by AngularJS's built-in expression **sandbox**, a security mechanism (present in older AngularJS versions) that restricts direct calls to dangerous global functions like `alert`.
6. Used a known sandbox-escape technique that reaches the global `Function` constructor indirectly via a scope object's `constructor` property, bypassing the direct-call restriction.

---

## Proof of Concept

**Payload used in the search box:**
```
{{$on.constructor('alert(1)')()}}
```

**Steps:**
1. Enter the payload above into the search box.
2. Click "Search".
3. AngularJS's digest cycle scans the `ng-app` node, finds the `{{ }}` expression, and evaluates it.
4. `$on.constructor` resolves to the JavaScript `Function` constructor (via AngularJS's internal scope object), which is then invoked with `'alert(1)'` as its body and immediately called — executing `alert(1)` as if it were `new Function('alert(1)')()`.
5. No angle brackets or double quotes are required anywhere in the payload, so the HTML encoding in place has no effect on this attack.

---

## Remediation

- **Avoid `ng-app` (or any live template engine) scanning untrusted content:** Do not let user-controlled data end up inside a DOM region actively scanned by AngularJS (or any client-side template engine) for expressions. Render user data as inert text outside the scope of template evaluation, or use `ng-non-bindable` on elements containing untrusted content.
- **HTML encoding is the wrong control for this vulnerability class:** This lab demonstrates that HTML encoding of `<`, `>`, and `"` is irrelevant when the execution mechanism is the framework's own expression evaluator rather than raw HTML parsing — the correct fix is architectural (don't expose user input to the template engine), not encoding-based.
- **Upgrade away from legacy AngularJS 1.x:** AngularJS 1.x reached end-of-life in January 2022 and receives no further security patches; known sandbox-escape techniques like this one will never be fixed. Migrating to a modern framework (Angular 2+, React, Vue) with strict contextual auto-escaping removes this entire vulnerability class.
- **Content Security Policy (CSP):** A strict CSP can limit the practical impact of a successful sandbox escape, though it does not prevent the underlying template injection itself.
